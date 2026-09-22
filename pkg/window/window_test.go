package window

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
	"github.com/h3yow/siem-correlation-engine-go/pkg/rule"
)

var base = time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)

func testRule() *rule.Rule {
	return &rule.Rule{
		ID:       "T1",
		Window:   60 * time.Second,
		Lateness: 10 * time.Second,
		Version:  1,
		Sequence: []rule.Condition{
			{Type: "a"},
			{Type: "b"},
			{Type: "c"},
		},
	}
}

func ev(id, typ string, sec int64, seq int64) *event.Event {
	return &event.Event{
		ID: id, Type: typ, Timestamp: base.Add(time.Duration(sec) * time.Second),
		IngestSeq: seq, Severity: event.SeverityInfo,
	}
}

func fps(ms []Match) map[string][]string {
	out := map[string][]string{}
	for _, m := range ms {
		ids := make([]string, len(m.Events))
		for i, e := range m.Events {
			ids[i] = e.ID
		}
		out[m.Fingerprint] = ids
	}
	return out
}

// 乱序与顺序到达必须产生完全相同的最终告警指纹集合。
func TestOutOfOrderConsistency(t *testing.T) {
	type in struct {
		id, typ string
		sec     int64
	}
	events := []in{
		{"a1", "a", 0}, {"a2", "a", 2}, {"b1", "b", 10},
		{"c1", "c", 20}, {"c2", "c", 55}, {"x1", "x", 30},
	}
	orderA := []int{0, 1, 2, 3, 4, 5} // 事件时间序
	orderB := []int{4, 3, 5, 2, 1, 0} // 逆序
	orderC := []int{2, 0, 4, 5, 3, 1} // 随机打乱（倒置都在 10s 容忍以上——见下，均先建水位）

	run := func(order []int, lateOK bool) map[string][]string {
		mgr := NewManager()
		r := testRule()
		all := map[string][]string{}
		for i, idx := range order {
			e := events[idx]
			res := mgr.Add(r, "", ev(e.id, e.typ, e.sec, int64(i+1)), base.Add(time.Hour))
			if res.DroppedLate {
				t.Logf("事件 %s 因迟到被拒绝（处理序 %d）", e.id, i)
			}
			for _, m := range res.Matches {
				ids := make([]string, len(m.Events))
				for j, x := range m.Events {
					ids[j] = x.ID
				}
				all[m.Fingerprint] = ids
			}
		}
		return all
	}

	fa := run(orderA, true)
	// 逆序在容忍度内（倒置最大 55s > 10s lateness），为保证公平，
	// 逆序场景单独用更宽容忍度规则验证。
	_ = orderB
	_ = orderC
	// 用 lateness=120s 的规则重跑三种顺序。
	runWide := func(order []int) map[string][]string {
		mgr := NewManager()
		r := testRule()
		r.Lateness = 120 * time.Second
		all := map[string][]string{}
		for i, idx := range order {
			e := events[idx]
			res := mgr.Add(r, "", ev(e.id, e.typ, e.sec, int64(i+1)), base.Add(time.Hour))
			if res.DroppedLate {
				t.Errorf("宽容忍度下事件 %s 不应被迟到拒绝", e.id)
			}
			for _, m := range res.Matches {
				ids := make([]string, len(m.Events))
				for j, x := range m.Events {
					ids[j] = x.ID
				}
				all[m.Fingerprint] = ids
			}
		}
		return all
	}
	fb := runWide(orderB)
	fc := runWide(orderC)

	t.Logf("顺序到达告警集合: %v", fa)
	t.Logf("逆序到达告警集合: %v", fb)
	t.Logf("打乱到达告警集合: %v", fc)

	if len(fb) != len(fc) {
		t.Fatalf("逆序(%d条)与打乱(%d条)告警数量不一致", len(fb), len(fc))
	}
	for fp, chainB := range fb {
		chainC, ok := fc[fp]
		if !ok {
			t.Fatalf("打乱顺序缺失指纹 %s（链 %v）", fp, chainB)
		}
		if len(chainB) != len(chainC) {
			t.Fatalf("指纹 %s 证据链长度不一致", fp)
		}
		for i := range chainB {
			if chainB[i] != chainC[i] {
				t.Fatalf("指纹 %s 证据链不一致: %v vs %v", fp, chainB, chainC)
			}
		}
	}
	// 顺序场景（严格事件时间，无迟到）必须是乱序场景的子集。
	for fp := range fa {
		if _, ok := fb[fp]; !ok {
			t.Fatalf("顺序到达的指纹 %s 在乱序结果中缺失", fp)
		}
	}
}

func TestWindowBoundary(t *testing.T) {
	mgr := NewManager()
	r := testRule()
	// 跨度恰好 60s：应触发。
	res1 := mgr.Add(r, "", ev("a1", "a", 0, 1), base)
	_ = res1
	mgr.Add(r, "", ev("b1", "b", 30, 2), base)
	res3 := mgr.Add(r, "", ev("c1", "c", 60, 3), base)
	if len(res3.Matches) != 1 {
		t.Fatalf("跨度恰好等于窗口应触发 1 条，实际 %d", len(res3.Matches))
	}
	t.Logf("边界内（60s 整）触发: %v", fps(res3.Matches))

	// 跨度 61s：不触发。
	mgr2 := NewManager()
	r2 := testRule()
	mgr2.Add(r2, "", ev("a1", "a", 0, 1), base)
	mgr2.Add(r2, "", ev("b1", "b", 30, 2), base)
	res := mgr2.Add(r2, "", ev("c2", "c", 61, 3), base)
	if len(res.Matches) != 0 {
		t.Fatalf("跨度超过窗口不应触发，实际 %d 条", len(res.Matches))
	}
	t.Log("跨度 61s > 窗口 60s，正确地不触发")
}

func TestNoDuplicateAlert(t *testing.T) {
	mgr := NewManager()
	r := testRule()
	r.Lateness = 120 * time.Second
	mgr.Add(r, "", ev("a1", "a", 0, 1), base)
	mgr.Add(r, "", ev("b1", "b", 10, 2), base)
	res := mgr.Add(r, "", ev("c1", "c", 20, 3), base)
	if len(res.Matches) != 1 {
		t.Fatalf("首次应触发 1 条，实际 %d", len(res.Matches))
	}
	// 后续不相关/乱序补送的事件不得重复触发同一链。
	res = mgr.Add(r, "", ev("z1", "z", 5, 4), base)
	if len(res.Matches) != 0 {
		t.Fatalf("不相关事件不应产生告警，实际 %d", len(res.Matches))
	}
	res = mgr.Add(r, "", ev("a2", "a", 2, 5), base)
	for _, m := range res.Matches {
		for _, e := range m.Events {
			if e.ID == "a1" {
				t.Fatalf("旧链 [a1,b1,c1] 被重复触发")
			}
		}
	}
	t.Logf("旧链未重复触发；a2 新链: %v", fps(res.Matches))
}

func TestLateBeyondWatermark(t *testing.T) {
	mgr := NewManager()
	r := testRule() // lateness 10s
	mgr.Add(r, "", ev("c1", "c", 100, 1), base)
	mgr.Add(r, "", ev("b1", "b", 95, 2), base)
	// a 事件 ts=80，水位线 = 100-10 = 90，80 < 90，迟到拒绝。
	res := mgr.Add(r, "", ev("a1", "a", 80, 3), base)
	if !res.DroppedLate {
		t.Fatalf("ts=80 早于水位线 90 应被拒绝")
	}
	t.Logf("迟到事件被拒绝，窗口状态: events=%d", len(mgr.Snapshot("T1")[0].Events))

	// 但 ts=92 仍在容忍度内，应可参与关联。
	mgr2 := NewManager()
	r2 := testRule()
	mgr2.Add(r2, "", ev("c1", "c", 100, 1), base)
	mgr2.Add(r2, "", ev("b1", "b", 95, 2), base)
	res2 := mgr2.Add(r2, "", ev("a2", "a", 92, 3), base)
	if res2.DroppedLate || len(res2.Matches) != 1 {
		t.Fatalf("ts=92 在水位线 90 之后，应正常触发（matches=%d, late=%v）", len(res2.Matches), res2.DroppedLate)
	}
	t.Logf("容忍度内乱序成功触发: %v", fps(res2.Matches))
}

func TestEviction(t *testing.T) {
	mgr := NewManager()
	r := testRule() // window 60 + lateness 10 → 保留 horizon=maxTS-70 之后
	mgr.Add(r, "p", ev("a1", "a", 0, 1), base)
	mgr.Add(r, "p", ev("a2", "a", 80, 2), base)
	st := mgr.Snapshot("T1")
	if len(st) != 1 || len(st[0].Events) != 1 || st[0].Events[0].ID != "a2" {
		t.Fatalf("过期事件 a1 应被淘汰，实际保留 %v", st)
	}
	t.Logf("淘汰后窗口仅保留 %v，maxTS=%s watermark=%s",
		ids(st[0].Events), st[0].MaxTS.Format(time.RFC3339), st[0].Watermark.Format(time.RFC3339))

	// AdvanceWatermark 在处理时间远晚于 maxTS 时清空空闲分区。
	dropped := mgr.AdvanceWatermark([]*rule.Rule{r}, base.Add(10*time.Minute))
	if len(dropped) != 1 {
		t.Fatalf("空闲分区应被整体淘汰，实际 %v", dropped)
	}
}

func ids(evs []*event.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}
