package snapshot_test

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// at 返回基准时间 +n 秒。
func at(n int) time.Time { return testBase.Add(time.Duration(n) * time.Second) }

func fail(n int, ip string) event.Event {
	return mkTestEvent(at(n), ip, "auth.failure", "login_failed", "root")
}

func locked(n int, ip string) event.Event {
	return mkTestEvent(at(n), ip, "auth.locked", "locked", "root")
}

// TestRestoreMidSequenceCompletesAfterRestart 覆盖必需场景一：
// "恢复点正好落在一个还没凑齐的序列中间"。
//
// 重启前只攒下 3/4 的事件（3 个失败，缺锁定），快照后在新进程补齐锁定：
// 必须与"从未重启"一样恰好产出 1 条 Fired，且指纹逐字节相同（不漏、不重）。
func TestRestoreMidSequenceCompletesAfterRestart(t *testing.T) {
	// 参照：进程不重启。
	ref := newTestEnv(30 * time.Second)
	if err := ref.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	seq := []event.Event{fail(0, "1.1.1.1"), fail(1, "1.1.1.1"), fail(2, "1.1.1.1"), locked(3, "1.1.1.1")}
	ref.feed(t, seq)

	// 重启：恢复点落在第 3 个事件之后（序列仍不完整，0 告警）。
	env := newTestEnv(30 * time.Second)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	env.feed(t, seq[:3])
	if len(env.alerts) != 0 {
		t.Fatalf("incomplete sequence before snapshot must not fire, got %d", len(env.alerts))
	}
	env2 := env.restart(t)
	env2.feed(t, seq[3:])

	if got := countFired(env2.alerts); got != 1 {
		t.Fatalf("after restore, completing the sequence should fire exactly once, got %d", got)
	}
	refSig := ref.conclusion()
	gotSig := env2.conclusion()
	if gotSig != refSig {
		t.Fatalf("重启后补齐序列结论与未重启不一致:\n got=%s\nwant=%s", gotSig, refSig)
	}
	t.Logf("恢复点落在未凑齐序列中间：恢复后补齐 => 1 条 Fired，指纹与未重启一致\n  %s", env2.alerts[0].DedupKey)
}

// TestRestoreLateAndOutOfOrderAcrossBoundary 覆盖必需场景二：
// "恢复前后有迟到、乱序事件跨过恢复边界"。
//
// 重启前：失败1、失败3、锁定（缺中间的失败2，且锁定先于"未来才到的"失败2），
// 水印已推进到 +3s；重启后：迟到的中间事件失败2(+2s)、一次乱序重放（重复投递）、
// 以及序列首事件的重复投递。结论必须与未重启完全一致：
// 迟到中间事件补齐序列 => 恰好 1 条 Fired；重复投递 => duplicate 拒绝，不重复告警。
func TestRestoreLateAndOutOfOrderAcrossBoundary(t *testing.T) {
	// 参照进程：到达顺序与"重启两段拼接后的总顺序"保持一致，
	// 这样签名（含拒绝）才可比。
	arrival := []event.Event{
		fail(0, "2.2.2.2"),
		fail(1, "2.2.2.2"),
		locked(3, "2.2.2.2"),
		fail(2, "2.2.2.2"), // 迟到的中间事件，补齐序列
		fail(1, "2.2.2.2"), // 乱序重放（重复投递）
		fail(0, "2.2.2.2"), // 跨边界的重复投递
	}

	ref := newTestEnv(60 * time.Second)
	if err := ref.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	ref.feed(t, arrival)

	// 重启进程：恢复点在锁定事件之后（序列尚缺中间失败2，无告警）。
	env := newTestEnv(60 * time.Second)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	env.feed(t, arrival[:3])
	if len(env.alerts) != 0 {
		t.Fatalf("missing middle event: no alert before snapshot, got %d", len(env.alerts))
	}
	env2 := env.restart(t)
	env2.feed(t, arrival[3:])

	if got := countFired(env2.alerts); got != 1 {
		t.Fatalf("迟到中间事件跨恢复边界补齐序列应恰好 1 条 Fired，got %d", got)
	}
	gotSig, refSig := env2.conclusion(), ref.conclusion()
	if gotSig != refSig {
		t.Fatalf("迟到/乱序/重复跨恢复边界结论与未重启不一致:\n got=%s\nwant=%s", gotSig, refSig)
	}
	t.Logf("迟到中间事件跨边界补齐序列不重不漏；跨边界重复投递被 duplicate 拒绝:\n  %s", env2.alerts[0].DedupKey)
}

// TestAlreadyFiredDoesNotRefireAfterRestore 重启前已发过的告警，
// 重启后重放同一序列不得再次冒出。
func TestAlreadyFiredDoesNotRefireAfterRestore(t *testing.T) {
	seq := []event.Event{fail(0, "3.3.3.3"), fail(1, "3.3.3.3"), fail(2, "3.3.3.3"), locked(3, "3.3.3.3")}

	env := newTestEnv(30 * time.Second)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	env.feed(t, seq)
	if got := countFired(env.alerts); got != 1 {
		t.Fatalf("want 1 fired before restart, got %d", got)
	}
	fingerprint := env.alerts[0].DedupKey

	env2 := env.restart(t)
	// 重启后乱序重放整个已告警序列：既不应产生新 Fired，
	// 摄取层也应把全部重复记录判为 duplicate。
	env2.feed(t, []event.Event{seq[3], seq[1], seq[2], seq[0]})
	if got := countFired(env2.alerts); got != 0 {
		t.Fatalf("already-fired sequence must not refire after restart, got %d", got)
	}
	dups := 0
	for _, r := range env2.rejected {
		if r.Reason == event.ReasonDuplicate {
			dups++
		}
	}
	if dups != len(seq) {
		t.Fatalf("重放 %d 条已摄取记录应全部 duplicate，got %d (rejected=%d)",
			len(seq), dups, len(env2.rejected))
	}
	t.Logf("重启前指纹 %s 的告警重启后不重复；重放全部判 duplicate", fingerprint)
}
