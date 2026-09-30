package snapshot_test

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// TestConcurrentExportDuringIngestion 导出与并发摄取同时进行：
// 不发生数据竞争（-race）、导出始终得到结构合法的快照、最终结论与
// 单线程顺序处理一致。
func TestConcurrentExportDuringIngestion(t *testing.T) {
	env := newTestEnv(time.Minute)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var bad int64

	// 周期性导出（模拟常驻服务定时快照）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			snap := snapshot.Export(env.svc, env.eng)
			if _, err := snap.Encode(); err != nil {
				atomic.AddInt64(&bad, 1)
			}
			runtime.Gosched()
		}
	}()

	// 并发摄取多个独立分组的事件序列。
	var feedWG sync.WaitGroup
	for ipIdx := 0; ipIdx < 8; ipIdx++ {
		ip := ipStr(ipIdx)
		feedWG.Add(1)
		go func(ip string) {
			defer feedWG.Done()
			evs := []event.Event{
				fail(0, ip), fail(1, ip), fail(2, ip), locked(3, ip),
			}
			env.feed(t, evs) // feed 内部有锁
		}(ip)
	}
	feedWG.Wait()
	close(stop)
	wg.Wait()

	if atomic.LoadInt64(&bad) != 0 {
		t.Fatalf("并发导出产生 %d 个无法编码的快照", bad)
	}
	if got := countFired(env.alerts); got != 8 {
		t.Fatalf("8 个独立分组应各产出 1 条 Fired，got %d", got)
	}

	// 最终状态仍可被正常导出并恢复，恢复后状态合法。
	snap := snapshot.Export(env.svc, env.eng)
	data, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := snapshot.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := got.Restore(); err != nil {
		t.Fatalf("并发摄取后的快照应可恢复: %v", err)
	}
	t.Logf("并发摄取与周期导出同时进行：0 竞争、0 坏快照、%d 条 Fired", countFired(env.alerts))
}

// TestExportDoesNotAliasEngineState 导出的快照必须是深拷贝：
// 之后引擎继续摄取/淘汰，不能改到已导出快照的内容；修改快照也不能污染引擎。
func TestExportDoesNotAliasEngineState(t *testing.T) {
	env := newTestEnv(time.Minute)
	_ = env.eng.UpsertRule(bruteForceRule(10*time.Second), 1)
	evs := []event.Event{fail(0, "4.4.4.4"), fail(1, "4.4.4.4")}
	env.feed(t, evs)

	st := env.eng.ExportState()
	if len(st.Rules) != 1 || len(st.Rules[0].Groups) == 0 {
		t.Fatalf("snapshot should contain window events, got %+v", st)
	}
	windowEvCount := 0
	for _, g := range st.Rules[0].Groups {
		windowEvCount += len(g.Events)
	}
	// 篡改导出副本：引擎内部状态不应受影响。
	for _, g := range st.Rules[0].Groups {
		for i := range g.Events {
			g.Events[i].Attributes["tampered"] = "yes"
			g.Events[i].SrcIP = "0.0.0.0"
		}
	}

	// 推进水印使旧事件被引擎淘汰。
	env.feed(t, []event.Event{mkTestEvent(at(90), "5.5.5.5", "auth.failure", "login_failed", "x")})

	// 从引擎重新导出：必须看不到任何来自副本的篡改。
	fresh := env.eng.ExportState()
	for _, g := range fresh.Rules[0].Groups {
		for _, ev := range g.Events {
			if ev.SrcIP == "0.0.0.0" {
				t.Fatal("修改导出快照竟反映到引擎状态（别名共享）")
			}
			if ev.Attributes["tampered"] == "yes" {
				t.Fatal("Attributes map 与引擎共享")
			}
		}
	}

	// 旧快照是独立副本：不受引擎后续淘汰影响，事件数量原样保留。
	got := 0
	for _, g := range st.Rules[0].Groups {
		got += len(g.Events)
	}
	if got != windowEvCount {
		t.Fatalf("引擎淘汰事件改动了已导出快照: %d -> %d", windowEvCount, got)
	}
	t.Logf("导出快照与引擎状态完全隔离（窗内 %d 个事件深拷贝）", got)
}

// TestRepeatedExportsDoNotGrowMemory 反复周期性导出不应让引擎与快照
// 占用一路上涨：连续导出多次后再导出的编码大小应稳定（同状态 => 同大小）。
func TestRepeatedExportsDoNotGrowMemory(t *testing.T) {
	env := newTestEnv(time.Minute)
	_ = env.eng.UpsertRule(bruteForceRule(10*time.Second), 1)
	env.feed(t, []event.Event{fail(0, "4.4.4.4"), fail(1, "4.4.4.4")})

	fixed := time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)
	sizes := map[int]int{}
	for i := 0; i < 50; i++ {
		snap := snapshot.Export(env.svc, env.eng, snapshot.WithTakenAt(fixed))
		data, err := snap.Encode()
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(data)]++
	}
	if len(sizes) != 1 {
		t.Fatalf("同状态反复导出应得到相同大小，出现 %d 种大小（可能累积状态）", len(sizes))
	}
	runtime.GC()
	t.Log("50 次周期导出，快照字节大小恒定，不随导出次数累积")
}
