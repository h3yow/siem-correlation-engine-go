package snapshot_test

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// TestRuleHotUpdateVersionSurvivesRestart 运行期改过规则后导出快照，
// 恢复后规则必须是导出时刻的版本与内容，且"热更新不丢状态、不重复告警"
// 的语义跨进程照旧成立。
func TestRuleHotUpdateVersionSurvivesRestart(t *testing.T) {
	env := newTestEnv(60 * time.Second)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	// 先在 v1 下积累不完整序列。
	partial := []event.Event{fail(100, "6.6.6.6"), fail(101, "6.6.6.6"), fail(102, "6.6.6.6")}
	env.feed(t, partial)

	// 热更新：窗口放宽到 30s，版本 2。
	updated := bruteForceRule(30 * time.Second)
	updated.Name = "SSH brute force (widened)"
	if err := env.eng.UpsertRule(updated, 2); err != nil {
		t.Fatalf("upsert v2: %v", err)
	}

	// 在 v2 生效状态下导出并恢复。
	env2 := env.restart(t)
	d := env2.eng.Detectors()["brute-force"]
	if d == nil {
		t.Fatal("rule missing after restore")
	}
	if d.RuleVersion() != 2 {
		t.Fatalf("restored rule version = %d, want 2", d.RuleVersion())
	}
	if d.Rule().Window != 30*time.Second {
		t.Fatalf("restored rule window = %s, want 30s", d.Rule().Window)
	}

	// 恢复后补齐锁定（+3s 仍在 30s 窗内）：基于保留状态产生 1 条 v2 告警。
	env2.feed(t, []event.Event{locked(103, "6.6.6.6")})
	if got := countFired(env2.alerts); got != 1 {
		t.Fatalf("after restore under v2 rule want 1 fired, got %d", got)
	}
	if env2.alerts[0].RuleVersion != 2 {
		t.Fatalf("alert after restore should carry rule v2, got v%d", env2.alerts[0].RuleVersion)
	}

	// 重放历史：已告警序列不得在恢复后重复触发（热更新去重语义延续）。
	before := len(env2.rejected)
	env2.feed(t, []event.Event{partial[2], locked(103, "6.6.6.6"), partial[0]})
	if got := countFired(env2.alerts) - 1; got != 0 {
		t.Fatalf("replay after restore must not refire, extra fired=%d", got)
	}
	dups := 0
	for _, r := range env2.rejected[before:] {
		if r.Reason == event.ReasonDuplicate {
			dups++
		}
	}
	if dups != 3 {
		t.Fatalf("3 条重放记录应全部 duplicate，got %d", dups)
	}
	t.Log("规则热更新版本与内容随快照恢复，保留状态在 v2 下补齐，且历史不重复告警")
}

// TestSuppressionBucketRestored 抑制桶跨重启恢复：静默期语义延续，
// 重启后的同聚合键命中仍为 suppressed，OccurrenceCnt 接续累计。
func TestSuppressionBucketRestored(t *testing.T) {
	env := newTestEnv(time.Hour)
	// 极长窗口 + 不约束 MaxGap，使每个独立 4 事件序列都能命中。
	r := bruteForceRule(48 * time.Hour)
	if err := env.eng.UpsertRule(r, 1); err != nil {
		t.Fatal(err)
	}
	cycle := func(start int, ip string) []event.Event {
		return []event.Event{
			fail(start, ip), fail(start+1, ip), fail(start+2, ip), locked(start+3, ip),
		}
	}
	env.feed(t, cycle(0, "7.7.7.7"))
	if got := countFired(env.alerts); got != 1 {
		t.Fatalf("first cycle should fire, got %d", got)
	}

	// 第二次命中在静默期内 => suppressed，计数 2。
	env.feed(t, cycle(10, "7.7.7.7"))
	if len(env.alerts) != 2 || env.alerts[1].Kind != "suppressed" || env.alerts[1].OccurrenceCnt != 2 {
		t.Fatalf("second cycle should be suppressed occ=2, got %+v", env.alerts)
	}

	env2 := env.restart(t)
	// 重启后第三次命中：桶已恢复 => 仍在静默期内 suppressed，计数接续为 3。
	env2.feed(t, cycle(20, "7.7.7.7"))
	if len(env2.alerts) != 1 {
		t.Fatalf("post-restore cycle should produce 1 conclusion, got %d", len(env2.alerts))
	}
	a := env2.alerts[0]
	if a.Kind != "suppressed" {
		t.Fatalf("post-restore hit should remain suppressed, got kind=%s", a.Kind)
	}
	if a.OccurrenceCnt != 3 {
		t.Fatalf("occurrence count should continue at 3 after restart, got %d", a.OccurrenceCnt)
	}
	if a.SuppressedBy == "" || a.AggregateKey == "" {
		t.Fatal("suppressed alert must retain suppressed-by and aggregate key")
	}
	t.Logf("抑制桶跨恢复延续：重启后命中 suppressed，occ=%d，by=%s", a.OccurrenceCnt, a.SuppressedBy)
}

// TestTooLateBoundaryConsistentAcrossRestart 水印跨重启恢复：
// 重启后超过 AllowedLateness 的迟到事件与未重启时一样被 too_late 拒绝。
func TestTooLateBoundaryConsistentAcrossRestart(t *testing.T) {
	env := newTestEnv(10 * time.Second)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	// 推进水印到 +60s。
	env.feed(t, []event.Event{
		fail(0, "8.8.8.8"), fail(1, "8.8.8.8"),
		fail(60, "9.9.9.9"),
	})
	env2 := env.restart(t)
	// +20s 事件相对水印 60s 已超出 10s 容忍 => too_late（参照进程同样如此）。
	stale := fail(20, "8.8.8.8")
	env2.feed(t, []event.Event{stale})

	var hasTooLate bool
	for _, r := range env2.rejected {
		if r.Reason == event.Reason("too_late") {
			hasTooLate = true
		}
	}
	if !hasTooLate {
		t.Fatalf("恢复水印后，超过容忍度的迟到事件应被 too_late 拒绝，got %+v", env2.rejected)
	}

	ref := newTestEnv(10 * time.Second)
	_ = ref.eng.UpsertRule(bruteForceRule(10*time.Second), 1)
	ref.feed(t, []event.Event{
		fail(0, "8.8.8.8"), fail(1, "8.8.8.8"),
		fail(60, "9.9.9.9"),
		stale,
	})
	if env2.conclusion() != ref.conclusion() {
		t.Fatalf("水印恢复后的 too_late 结论与未重启不一致:\n got=%s\nwant=%s",
			env2.conclusion(), ref.conclusion())
	}
	t.Log("水印跨恢复一致：超出 AllowedLateness 的事件仍被明确 too_late 拒绝")
}
