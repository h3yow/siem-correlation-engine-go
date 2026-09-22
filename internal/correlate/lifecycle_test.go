package correlate

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

func sequenceEvents() []event.Event {
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	return []event.Event{
		mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root"),
	}
}

func TestNoDuplicateAlertOnReprocessing(t *testing.T) {
	evSeq = 0
	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute}
	e := NewEngine(cfg, 30*time.Second)
	_ = e.UpsertRule(bruteForceRule(10*time.Second), 1)

	evs := sequenceEvents()
	r1 := e.ProcessBatch(evs)
	if n := len(firedAlerts(r1.Alerts)); n != 1 {
		t.Fatalf("first run want 1 fired, got %d", n)
	}
	key := firedAlerts(r1.Alerts)[0].DedupKey

	// 模拟同一批历史事件以另一种乱序顺序被重放（结论必须可复现）：
	// 已告警序列不得再次告警。
	r2 := e.ProcessBatchShuffled(evs, 7)
	if n := len(firedAlerts(r2.Alerts)); n != 0 {
		t.Fatalf("reprocess same sequence must not fire again, got %d", n)
	}
	t.Logf("同一序列指纹 %s 仅告警一次；乱序重放 0 条新告警", key)
}

func TestTwoIndependentSequencesEachFire(t *testing.T) {
	evSeq = 0
	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id", "src_ip"}, QuietFor: 0}
	// QuietFor=0 => 不抑制，独立序列都应 Fired。
	cfg.QuietFor = time.Nanosecond
	e := NewEngine(cfg, 30*time.Second)
	_ = e.UpsertRule(bruteForceRule(10*time.Second), 1)

	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	var evs []event.Event
	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		evs = append(evs,
			mkEv(at(0), ip, "auth.failure", "login_failed", "root"),
			mkEv(at(1), ip, "auth.failure", "login_failed", "root"),
			mkEv(at(2), ip, "auth.failure", "login_failed", "root"),
			mkEv(at(3), ip, "auth.locked", "locked", "root"),
		)
	}
	res := e.ProcessBatchShuffled(evs, 123)
	if n := len(firedAlerts(res.Alerts)); n != 2 {
		t.Fatalf("two independent src_ip sequences want 2 fired, got %d", n)
	}
	keys := map[string]bool{}
	for _, a := range firedAlerts(res.Alerts) {
		keys[a.DedupKey] = true
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 distinct fingerprints, got %d", len(keys))
	}
	t.Logf("两个独立分组各产生一条不同指纹告警: %d", len(keys))
}

func TestRuleHotUpdatePreservesStateAndNoRefire(t *testing.T) {
	evSeq = 0
	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute}
	e := NewEngine(cfg, 60*time.Second)
	_ = e.UpsertRule(bruteForceRule(10*time.Second), 1)

	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	// 先积累不完整窗口：3 个失败，尚无锁定。
	partial := []event.Event{
		mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root"),
	}
	r0 := e.ProcessBatch(partial)
	if len(r0.Alerts) != 0 {
		t.Fatalf("partial sequence should not fire")
	}

	// 运行期更新规则：放宽窗口到 30s，版本升到 2。窗口状态必须保留。
	updated := bruteForceRule(30 * time.Second)
	updated.Name = "SSH brute force (widened)"
	if err := e.UpsertRule(updated, 2); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if e.rules["brute-force"].RuleVersion() != 2 {
		t.Fatalf("rule version should be 2")
	}

	// 用更新后的规则补齐锁定事件（仍在新窗口内）：应基于保留状态产生告警，
	// 且 RuleVersion=2。
	lock := mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root")
	r1 := e.ProcessBatch([]event.Event{lock})
	fired := firedAlerts(r1.Alerts)
	if len(fired) != 1 {
		t.Fatalf("after rule update, retained state should still fire, got %d", len(fired))
	}
	if fired[0].RuleVersion != 2 {
		t.Fatalf("alert should carry new rule version 2, got %d", fired[0].RuleVersion)
	}
	t.Logf("规则热更新后窗口状态保留，新告警携带 v%d: %s", fired[0].RuleVersion, fired[0].Reason)

	// 再重放历史事件：已产生的告警不得因版本变化重复触发。
	r2 := e.ProcessBatchShuffled(append(partial, lock), 99)
	if n := len(firedAlerts(r2.Alerts)); n != 0 {
		t.Fatalf("historical alerts must not refire after update, got %d", n)
	}
	t.Log("规则变更后重放历史事件：0 条重复告警")
}

func TestSuppressionAggregatesHighFrequency(t *testing.T) {
	evSeq = 0
	cfg := rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       time.Minute,
		MaxOccurrences: 50,
	}
	e := NewEngine(cfg, 10*time.Minute)
	r := bruteForceRule(time.Hour)
	r.MaxGap = 5 * time.Second // 攻击步骤必须紧凑，避免跨周期自由组合
	_ = e.UpsertRule(r, 1)

	// 同一 src_ip 连续完成 3 次"3 失败 + 1 锁定"序列（每周期时间不同，
	// 周期间隔 10s > MaxGap，因此每个锁定事件只规范命中本周期序列）。
	var evs []event.Event
	for cycle := 0; cycle < 3; cycle++ {
		s := cycle * 10
		evs = append(evs,
			mkEv(base.Add(time.Duration(s+0)*time.Second), "5.5.5.5", "auth.failure", "login_failed", "root"),
			mkEv(base.Add(time.Duration(s+1)*time.Second), "5.5.5.5", "auth.failure", "login_failed", "root"),
			mkEv(base.Add(time.Duration(s+2)*time.Second), "5.5.5.5", "auth.failure", "login_failed", "root"),
			mkEv(base.Add(time.Duration(s+3)*time.Second), "5.5.5.5", "auth.locked", "locked", "root"),
		)
	}
	res := e.ProcessBatch(evs)
	var firedN, suppressedN int
	for _, a := range res.Alerts {
		switch a.Kind {
		case alert.KindFired:
			firedN++
			t.Logf("Fired  agg=%s occ=%d", a.AggregateKey, a.OccurrenceCnt)
		case alert.KindSuppressed:
			suppressedN++
			t.Logf("Suppressed agg=%s occ=%d by=%s", a.AggregateKey, a.OccurrenceCnt, a.SuppressedBy)
		}
	}
	if firedN != 1 {
		t.Fatalf("want 1 fired within quiet window, got %d", firedN)
	}
	if suppressedN != 2 {
		t.Fatalf("want 2 suppressed, got %d", suppressedN)
	}
	last := res.Alerts[len(res.Alerts)-1]
	if last.OccurrenceCnt != 3 {
		t.Fatalf("aggregated occurrence count should reach 3, got %d", last.OccurrenceCnt)
	}
	if last.AggregateKey == "" || last.SuppressedBy == "" {
		t.Fatalf("suppressed alert must explain aggregate key and suppressed-by")
	}
}
