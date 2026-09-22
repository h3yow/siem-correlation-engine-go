package engine

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
	"github.com/h3yow/siem-correlation-engine-go/pkg/parser"
	"github.com/h3yow/siem-correlation-engine-go/pkg/rule"
)

var tbase = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

func newTestEngine(t *testing.T, logBuf *bytes.Buffer) *Engine {
	logger := log.New(logBuf, "", 0)
	e := New(Config{
		MaxFutureSkewSec: 600,
		MaxAgeSec:        86400 * 30,
		HistoryLimit:     1000,
		Logger:           logger,
		Now:              func() time.Time { return tbase.Add(2 * time.Hour) },
	})
	e.Registry().Register(parser.NewJSONParser())
	e.Registry().Register(parser.NewKVParser())
	e.Registry().Register(parser.NewCSVParser())
	return e
}

func jline(id, typ string, sec int64, subject string) string {
	return fmt.Sprintf(`{"id":"%s","ts":"%s","type":"%s","severity":"high","subject":"%s"}`,
		id, tbase.Add(time.Duration(sec)*time.Second).Format(time.RFC3339), typ, subject)
}

func threeStepRule(lateness time.Duration) *rule.Rule {
	return &rule.Rule{
		ID: "ABC", Name: "三步关联",
		Window:   60 * time.Second,
		Lateness: lateness,
		GroupBy:  []string{"subject"},
		Version:  1,
		Sequence: []rule.Condition{{Type: "a"}, {Type: "b"}, {Type: "c"}},
	}
}

func firedSet(e *Engine) map[string]bool {
	out := map[string]bool{}
	for _, a := range e.Alerts() {
		if !a.Suppressed {
			out[a.Fingerprint] = true
		}
	}
	return out
}

// 并发摄取：多个 goroutine 同时喂入乱序事件，告警集合必须确定且完整。
func TestConcurrentIngest(t *testing.T) {
	var buf bytes.Buffer
	e := newTestEngine(t, &buf)
	e.Start()
	if _, err := e.UpdateRule(threeStepRule(120 * time.Second)); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		jline("c1", "c", 20, "bob"),
		jline("a1", "a", 0, "bob"),
		jline("b1", "b", 10, "bob"),
		// 另一个分区，独立成立
		jline("a2", "a", 0, "alice"),
		jline("b2", "b", 10, "alice"),
		jline("c2", "c", 20, "alice"),
		// 畸形输入混入
		`{broken`,
		`{"id":"x","type":"a"}`,
	}
	var wg sync.WaitGroup
	for i := range lines {
		wg.Add(1)
		go func(line string) { defer wg.Done(); e.Ingest(line, "s1") }(lines[i])
	}
	wg.Wait()
	e.Stop()

	fs := firedSet(e)
	if len(fs) != 2 {
		t.Fatalf("两个分区应各触发 1 条告警，实际 %d: %v", len(fs), fs)
	}
	if !strings.Contains(buf.String(), "[reject] malformed_record") ||
		!strings.Contains(buf.String(), "[reject] missing_timestamp") {
		t.Fatalf("畸形输入拒绝原因日志缺失")
	}
	t.Logf("并发摄取后触发 %d 条告警；拒绝原因可区分", len(fs))
	t.Logf("窗口状态日志样例:\n%s", grepWindow(&buf))
}

// 乱序 vs 顺序：最终非抑制告警指纹集合必须一致。
func TestOrderIndependence(t *testing.T) {
	build := func(order []int) (*Engine, *bytes.Buffer) {
		var buf bytes.Buffer
		e := newTestEngine(t, &buf)
		if _, err := e.UpdateRule(threeStepRule(120 * time.Second)); err != nil {
			t.Fatal(err)
		}
		evs := []string{
			jline("a1", "a", 0, "u"),
			jline("a2", "a", 2, "u"),
			jline("b1", "b", 10, "u"),
			jline("c1", "c", 20, "u"),
			jline("c2", "c", 55, "u"),
		}
		for _, i := range order {
			r := e.IngestSync(evs[i], "s")
			if len(r.Rejected) != 0 {
				t.Fatalf("事件不应被拒绝: %+v", r.Rejected)
			}
		}
		return e, &buf
	}
	e1, _ := build([]int{0, 1, 2, 3, 4})
	e2, buf2 := build([]int{4, 3, 2, 1, 0})
	e3, _ := build([]int{2, 0, 4, 3, 1})
	f1, f2, f3 := firedSet(e1), firedSet(e2), firedSet(e3)
	t.Logf("顺序=%v 逆序=%v 打乱=%v", len(f1), len(f2), len(f3))
	t.Logf("逆序判定日志:\n%s", grepWindow(buf2))
	if len(f1) != len(f2) || len(f2) != len(f3) {
		t.Fatalf("三种顺序告警数量不一致: %d/%d/%d", len(f1), len(f2), len(f3))
	}
	for fp := range f1 {
		if !f2[fp] || !f3[fp] {
			t.Fatalf("指纹 %s 未在全部顺序下一致出现", fp)
		}
	}
}

// 规则更新：更新既有规则不丢窗口状态、不重复触发历史告警。
func TestRuleUpdatePreservesState(t *testing.T) {
	var buf bytes.Buffer
	e := newTestEngine(t, &buf)
	r := threeStepRule(120 * time.Second)
	if _, err := e.UpdateRule(r); err != nil {
		t.Fatal(err)
	}
	e.IngestSync(jline("a1", "a", 0, "u"), "s")
	e.IngestSync(jline("b1", "b", 10, "u"), "s")

	// 运行期更新规则（如调描述/版本），状态保留。
	r2 := threeStepRule(120 * time.Second)
	r2.Version = 2
	r2.Name = "改名后的规则"
	if rev, err := e.UpdateRule(r2); err != nil || rev == 0 {
		t.Fatalf("规则更新失败: rev=%d err=%v", rev, err)
	}
	st := e.windows.Snapshot("ABC")
	if len(st) != 1 || len(st[0].Events) != 2 {
		t.Fatalf("规则更新后窗口状态丢失: %+v", st)
	}
	res := e.IngestSync(jline("c1", "c", 20, "u"), "s")
	if len(res.Alerts) != 1 || res.Alerts[0].RuleVersion != 2 {
		t.Fatalf("更新后规则应在保留状态上触发且版本为 v2: %+v", res.Alerts)
	}
	if len(e.Alerts()) != 1 {
		t.Fatalf("历史链不得重复触发，实际总告警 %d", len(e.Alerts()))
	}
	t.Logf("规则更新保留状态并成功触发: %s\n%s", res.Alerts[0].Reason, grepWindow(&buf))
}

// 新规则在运行期加入时对历史事件回放；删除后重加，旧指纹必须被抑制而非重复告警。
func TestNewRuleReplayAndDeleteReadd(t *testing.T) {
	var buf bytes.Buffer
	e := newTestEngine(t, &buf)
	r := threeStepRule(120 * time.Second)
	r.DedupWindow = 0 // 永久去重
	if _, err := e.UpdateRule(r); err != nil {
		t.Fatal(err)
	}
	e.IngestSync(jline("a1", "a", 0, "u"), "s")
	e.IngestSync(jline("b1", "b", 10, "u"), "s")
	e.IngestSync(jline("c1", "c", 20, "u"), "s")
	if len(firedSet(e)) != 1 {
		t.Fatalf("原始规则应触发 1 条")
	}

	// 删除规则后以相同定义重新加入（模拟规则变更回滚）。
	if !e.DeleteRule("ABC") {
		t.Fatal("删除失败")
	}
	if _, err := e.UpdateRule(threeStepRule(120 * time.Second)); err != nil {
		t.Fatal(err)
	}
	all := e.Alerts()
	last := all[len(all)-1]
	if !last.Suppressed {
		t.Fatalf("重加规则回放历史产生的旧告警必须被抑制，实际 fired: %v", last.EventIDs)
	}
	t.Logf("删除后重加，历史指纹被抑制: events=%v count=%d", last.EventIDs, last.Count)

	// 全新证据链仍可正常触发。
	res := e.IngestSync(jline("c2", "c", 25, "u"), "s")
	if len(res.Alerts) == 0 || res.Alerts[0].Suppressed {
		t.Fatalf("新证据链应正常触发，实际 %+v", res.Alerts)
	}
	t.Logf("新证据链触发: %v\n%s", res.Alerts[0].EventIDs, grepWindow(&buf))
}

// 分区隔离：不同 subject 的事件不得跨分区关联。
func TestPartitionIsolation(t *testing.T) {
	var buf bytes.Buffer
	e := newTestEngine(t, &buf)
	if _, err := e.UpdateRule(threeStepRule(120 * time.Second)); err != nil {
		t.Fatal(err)
	}
	e.IngestSync(jline("a1", "a", 0, "bob"), "s")
	e.IngestSync(jline("b1", "b", 10, "alice"), "s")
	e.IngestSync(jline("c1", "c", 20, "carol"), "s")
	if len(e.Alerts()) != 0 {
		t.Fatalf("跨分区事件不得关联，实际 %d 条告警", len(e.Alerts()))
	}
	t.Log("三个不同分区的事件正确地未关联")
}

// 迟到与畸形输入在引擎层给出可区分拒绝原因。
func TestEngineRejectReasons(t *testing.T) {
	var buf bytes.Buffer
	e := newTestEngine(t, &buf)
	r := threeStepRule(5 * time.Second)
	if _, err := e.UpdateRule(r); err != nil {
		t.Fatal(err)
	}
	e.IngestSync(jline("c1", "c", 100, "u"), "s")
	e.IngestSync(jline("b1", "b", 95, "u"), "s")
	res := e.IngestSync(jline("a1", "a", 80, "u"), "s") // 水位线 90
	found := false
	for _, rr := range res.Rejected {
		if rr.Reason == event.RejectLateDropped {
			found = true
			t.Logf("迟到拒绝明细: %s", rr.Detail)
		}
	}
	if !found {
		t.Fatalf("应返回 late_beyond_watermark，实际 %+v", res.Rejected)
	}

	res2 := e.IngestSync(`{"id":"z","ts":"bad","type":"x"}`, "s")
	if len(res2.Rejected) != 1 || res2.Rejected[0].Reason != event.RejectBadTimestamp {
		t.Fatalf("坏时间戳应给出 bad_timestamp，实际 %+v", res2.Rejected)
	}
	res3 := e.IngestSync(jline("a99", "a", 0, "newu"), "s")
	if len(res3.Rejected) != 0 {
		t.Fatalf("新分区首次出现的事件不应被拒绝: %+v", res3.Rejected)
	}
	res3 = e.IngestSync(jline("a99", "a", 0, "newu"), "s")
	if res3.Rejected[0].Reason != event.RejectDuplicateID {
		t.Fatalf("重复 ID 应给出 duplicate_event_id，实际 %+v", res3.Rejected)
	}
}

// Housekeep 淘汰空闲窗口。
func TestHousekeep(t *testing.T) {
	var buf bytes.Buffer
	e := newTestEngine(t, &buf)
	r := threeStepRule(120 * time.Second)
	if _, err := e.UpdateRule(r); err != nil {
		t.Fatal(err)
	}
	e.IngestSync(jline("a1", "a", 0, "u"), "s")
	// Now 是 tbase+2h，远超 window+2*lateness，分区应被整体淘汰。
	w, _ := e.Housekeep()
	if w != 1 {
		t.Fatalf("应淘汰 1 个空闲分区，实际 %d", w)
	}
	if len(e.windows.Snapshot("ABC")) != 0 {
		t.Fatal("淘汰后不应残留窗口状态")
	}
}

func grepWindow(buf *bytes.Buffer) string {
	var out []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "[window]") || strings.Contains(line, "[fire]") || strings.Contains(line, "[late]") {
			out = append(out, "  "+line)
		}
	}
	if len(out) == 0 {
		return "(无窗口日志)"
	}
	return strings.Join(out, "\n") + "\n"
}
