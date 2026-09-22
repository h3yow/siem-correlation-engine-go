package correlate

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

var base = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// mkEv 构造一个时间确定、ID 确定的事件（ID 直接用序号，全序清晰）。
var evSeq = 0

func mkEv(at time.Time, srcIP, evType, action, user string) event.Event {
	evSeq++
	return event.Event{
		ID:         idFor(evSeq),
		OccurredAt: at,
		Source:     "sshd",
		EventType:  evType,
		SrcIP:      srcIP,
		User:       user,
		Action:     action,
		SrcHost:    "web-01",
	}
}

func idFor(n int) string {
	return "e-" + pad(n)
}

func pad(n int) string {
	s := ""
	for x := n; x < 100000; x *= 10 {
		s += "0"
	}
	return s + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func bruteForceRule(win time.Duration) rule.Rule {
	return rule.Rule{
		ID:       "brute-force",
		Name:     "SSH brute force",
		Severity: event.SeverityHigh,
		Window:   win,
		GroupBy:  "src_ip",
		Pattern: []rule.Match{
			{EventType: "auth.failure"},
			{EventType: "auth.failure"},
			{EventType: "auth.failure"},
			{EventType: "auth.locked"},
		},
	}
}

func firedAlerts(as []alert.Alert) []alert.Alert {
	var out []alert.Alert
	for _, a := range as {
		if a.Kind == alert.KindFired {
			out = append(out, a)
		}
	}
	return out
}

func newTestEngine(t *testing.T) (*Engine, time.Duration) {
	t.Helper()
	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute, MaxOccurrences: 10}
	e := NewEngine(cfg, 30*time.Second)
	if err := e.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatalf("upsert rule: %v", err)
	}
	return e, 10 * time.Second
}

func TestOrderedSequenceFiresOnce(t *testing.T) {
	evSeq = 0
	e, _ := newTestEngine(t)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }

	evs := []event.Event{
		mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root"),
	}
	res := e.ProcessBatch(evs)
	if got := len(firedAlerts(res.Alerts)); got != 1 {
		t.Fatalf("want exactly 1 fired alert, got %d (all=%d)", got, len(res.Alerts))
	}
	a := firedAlerts(res.Alerts)[0]
	if len(a.Evidence) != 4 {
		t.Fatalf("want 4 evidence, got %d", len(a.Evidence))
	}
	t.Logf("命中告警: %s\n判定依据: %s", a.DedupKey, a.Reason)
	t.Log("\n" + e.DumpState())
}

func TestOutOfOrderGivesSameConclusion(t *testing.T) {
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	signature := func(as []alert.Alert) string {
		var s string
		for _, a := range as {
			s += string(a.Kind) + ":" + a.RuleID + ":" + a.DedupKey + "|"
		}
		return s
	}

	var sigs []string
	for _, seed := range []int64{1, 2, 3, 42, 99} {
		evSeq = 0
		// 每个 run 使用同一批事件对象的副本，但 mkEv 会推进全局序号；
		// 为保证跨 run 的 ID 一致，每次都重新以相同顺序生成。
		batch := []event.Event{
			mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
			mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
			mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root"),
			mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root"),
		}
		cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute, MaxOccurrences: 10}
		eng := NewEngine(cfg, 30*time.Second)
		_ = eng.UpsertRule(bruteForceRule(10*time.Second), 1)
		res := eng.ProcessBatchShuffled(batch, seed)
		if len(firedAlerts(res.Alerts)) != 1 {
			t.Fatalf("seed %d: want 1 fired, got %d", seed, len(firedAlerts(res.Alerts)))
		}
		sigs = append(sigs, signature(res.Alerts))
	}
	for i := 1; i < len(sigs); i++ {
		if sigs[i] != sigs[0] {
			t.Fatalf("乱序结论不一致: %q vs %q", sigs[0], sigs[i])
		}
	}
	t.Logf("5 种不同乱序到达顺序 => 同一告警签名 %s", sigs[0])
}

func TestWindowBoundary(t *testing.T) {
	tests := []struct {
		name     string
		span     time.Duration // 首事件到锁定事件的跨度
		wantFire bool
	}{
		{"within window", 10 * time.Second, true},  // 恰好等于窗长：合法
		{"beyond window", 11 * time.Second, false}, // 超窗：不命中
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evSeq = 0
			e, _ := newTestEngine(t)
			span := tc.span
			evs := []event.Event{
				mkEv(base, "1.1.1.1", "auth.failure", "login_failed", "root"),
				mkEv(base.Add(span/3), "1.1.1.1", "auth.failure", "login_failed", "root"),
				mkEv(base.Add(2*span/3), "1.1.1.1", "auth.failure", "login_failed", "root"),
				mkEv(base.Add(span), "1.1.1.1", "auth.locked", "locked", "root"),
			}
			res := e.ProcessBatch(evs)
			got := len(firedAlerts(res.Alerts)) == 1
			if got != tc.wantFire {
				t.Fatalf("span=%s wantFire=%v got=%v", span, tc.wantFire, got)
			}
			t.Logf("窗口边界 span=%s window=10s => fired=%v", span, got)
		})
	}
}

func TestExpiredStateIsEvicted(t *testing.T) {
	evSeq = 0
	e, _ := newTestEngine(t)
	// 放入两个失败事件。
	e.ProcessBatch([]event.Event{
		mkEv(base, "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(base.Add(1*time.Second), "1.1.1.1", "auth.failure", "login_failed", "root"),
	})
	// 推进到 base+40s，使 10s 窗口状态过期淘汰。
	advance := mkEv(base.Add(40*time.Second), "9.9.9.9", "auth.failure", "login_failed", "other")
	e.ProcessBatch([]event.Event{advance})

	for _, d := range e.Detectors() {
		for _, st := range d.Snapshot() {
			for _, id := range st.EventIDs {
				if id == "e-00001" || id == "e-00002" {
					t.Fatalf("过期事件 %s 未被淘汰", id)
				}
			}
		}
	}
	t.Log("\n" + e.DumpState())
	t.Log("超过 window 的旧事件与部分匹配链已被水印淘汰")
}

func TestLateEventWithinLatenessStillDetected(t *testing.T) {
	evSeq = 0
	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute, MaxOccurrences: 10}
	e := NewEngine(cfg, 30*time.Second)
	_ = e.UpsertRule(bruteForceRule(10*time.Second), 1)

	// 第一批：两个失败 + 锁定（缺第三个失败，序列不完整，水印推进到 +3s）。
	early := []event.Event{
		mkEv(base, "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(base.Add(1*time.Second), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(base.Add(3*time.Second), "1.1.1.1", "auth.locked", "locked", "root"),
	}
	res := e.ProcessBatch(early)
	if len(firedAlerts(res.Alerts)) != 0 {
		t.Fatalf("序列不完整不应告警")
	}

	// 第二批：迟到但仍在 AllowedLateness 内的"中间"失败（事件时间 +2s，
	// 既不是新水印也不是末事件）。全量重枚举必须补齐序列 => 1 条告警。
	late := mkEv(base.Add(2*time.Second), "1.1.1.1", "auth.failure", "login_failed", "root")
	res = e.ProcessBatch([]event.Event{late})
	if len(firedAlerts(res.Alerts)) != 1 {
		t.Fatalf("迟到的中间事件（allowed_lateness 内）应补齐序列，got fired=%d", len(firedAlerts(res.Alerts)))
	}
	a := firedAlerts(res.Alerts)[0]
	want := "e-000001>e-000002>e-000004>e-000003"
	if a.DedupKey != want {
		t.Fatalf("规范序列指纹应为 %s, got %s", want, a.DedupKey)
	}
	t.Logf("迟到的中间事件补齐序列，未漏告警: %s", a.DedupKey)

	// 推进水印到较远位置后，超过容忍度的过迟事件必须被显式拒绝。
	advance := mkEv(base.Add(60*time.Second), "9.9.9.9", "auth.failure", "login_failed", "other")
	e.ProcessBatch([]event.Event{advance})
	stale := mkEv(base.Add(10*time.Second), "1.1.1.1", "auth.failure", "login_failed", "root")
	res = e.ProcessBatch([]event.Event{stale})
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != event.Reason("too_late") {
		t.Fatalf("过迟事件应以 too_late 拒绝, got %+v", res.Rejected)
	}
	t.Logf("超过容忍度的事件被显式拒绝: reason=%s detail=%s",
		res.Rejected[0].Reason, res.Rejected[0].Detail)
}
