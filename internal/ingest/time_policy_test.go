package ingest

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// clock 与口径：墙钟固定在 t0，口径收紧为 30s 未来容忍 / 2m 最早回溯。
func policyClock() (time.Time, TimePolicy) {
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	return t0, TimePolicy{MaxFutureSkew: 30 * time.Second, MinAge: 2 * time.Minute}
}

func jsonRecord(at time.Time, tag string) string {
	return `{"timestamp":"` + at.UTC().Format(time.RFC3339) +
		`","source":"sshd","event_type":"auth.failure","src_ip":"1.1.1.1","tag":"` + tag + `"}`
}

// TestTimePolicyRestoreOverridesConstructorSetting 回归核心：即使恢复方
// 构造 Normalizer/Service 时用的是默认口径，恢复后也必须以快照口径为准，
// 边界附近记录的结论随之改变（默认会放行的未来/陈旧记录被收紧口径拒绝）。
func TestTimePolicyRestoreOverridesConstructorSetting(t *testing.T) {
	t0, policy := policyClock()

	// 原进程：非默认口径运行。
	old := NewService(NewNormalizer(policy.MaxFutureSkew, policy.MinAge))
	old.norm.SetClock(func() time.Time { return t0 })
	seen, dup := old.ExportState()
	exported := old.ExportTimePolicy()
	if exported != policy {
		t.Fatalf("导出口径应为 %+v, got %+v", policy, exported)
	}

	cases := []struct {
		name   string
		at     time.Time
		accept bool
		reason event.Reason
	}{
		{"at-future-edge", t0.Add(30 * time.Second), true, ""},
		{"1s-over-future", t0.Add(31 * time.Second), false, event.ReasonFutureEvent},
		{"at-old-edge", t0.Add(-120 * time.Second), true, ""},
		{"1s-over-old", t0.Add(-121 * time.Second), false, event.ReasonTooOld},
	}
	// 参照：原进程上逐条判定。
	refOutcomes := map[string]string{}
	for i, c := range cases {
		raw := jsonRecord(c.at, "ref-"+c.name)
		r := old.Ingest(raw)
		if r.Accepted() != c.accept {
			t.Fatalf("参照[%d:%s] accept 期望 %v", i, c.name, c.accept)
		}
		if r.Accepted() {
			refOutcomes[raw] = "accept"
		} else {
			if r.Rejected.Reason != c.reason {
				t.Fatalf("参照[%d:%s] reason 期望 %s got %s", i, c.name, c.reason, r.Rejected.Reason)
			}
			refOutcomes[raw] = string(r.Rejected.Reason)
		}
	}

	// 新进程：刻意用默认口径（1h/0）构造，再用快照恢复（口径必须被覆盖）。
	news := NewService(nil)
	news.norm.SetClock(func() time.Time { return t0 })
	if p := news.ExportTimePolicy(); p.MaxFutureSkew != DefaultMaxFutureSkew || p.MinAge != DefaultMinAge {
		t.Fatalf("恢复前应为默认口径, got %+v", p)
	}
	// 恢复前先证明默认口径会放行进界外记录（即测试确实有区分度）。
	if r := news.Ingest(jsonRecord(t0.Add(31*time.Second), "probe-default-future")); !r.Accepted() {
		t.Fatalf("默认口径应放行 +31s（31s 远在 1h 内）, got %+v", r.Rejected)
	}
	// 探针占用去重表，恢复会被快照 seen 整体替换；用独立 raw 不影响后续断言。

	if err := news.RestoreState(seen, dup, exported); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if p := news.ExportTimePolicy(); p != policy {
		t.Fatalf("恢复后口径必须等于快照口径, got %+v want %+v", p, policy)
	}

	for _, c := range cases {
		raw := jsonRecord(c.at, "new-"+c.name)
		r := news.Ingest(raw)
		got := "accept"
		if !r.Accepted() {
			got = string(r.Rejected.Reason)
		}
		// 参照键不同（tag 不同），按 name 比对期望值。
		want := "accept"
		if !c.accept {
			want = string(c.reason)
		}
		if got != want {
			t.Fatalf("恢复后[%s] 期望 %s got %s", c.name, want, got)
		}
		t.Logf("恢复后边界 %-16s => %s", c.name, got)
	}
}

// TestTimePolicyAppliesUnderConcurrentAccess ApplyTimePolicy 与并发 Normalize
// 竞争时必须无数据竞争（由 -race 把关），且套用后新判定即时生效。
func TestTimePolicyAppliesUnderConcurrentAccess(t *testing.T) {
	t0, _ := policyClock()
	n := NewNormalizer(time.Hour, 0)
	n.SetClock(func() time.Time { return t0 })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			n.ApplyTimePolicy(TimePolicy{MaxFutureSkew: 30 * time.Second, MinAge: 2 * time.Minute})
		}
	}()
	for i := 0; i < 200; i++ {
		fields := map[string]string{
			"timestamp": t0.Format(time.RFC3339), "source": "sshd",
			"event_type": "auth.failure", "src_ip": "1.1.1.1",
		}
		_, _ = n.Normalize("json", fields, jsonRecord(t0, "race"))
	}
	<-done
}
