package ingest

import (
	"errors"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// tpRaw 构造一条时间戳相对 base 偏移 d 的 JSON 记录。
func tpRaw(d time.Duration) string {
	return `{"timestamp":"` +
		time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC).Add(d).Format(time.RFC3339Nano) +
		`","source":"sshd","event_type":"net.connection","action":"allow","src_ip":"1.1.1.1"}`
}

// TestTimePolicyExportAndApply 非默认口径可导出、恢复时强制覆盖调用方设置；
// 边界记录（now+90s 接受 / now+91s 拒绝 / now-2h 接受 / now-2h-1ns 拒绝）
// 在"原服务"与"默认设置恢复的新服务"上逐条一致。
func TestTimePolicyExportAndApply(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	future, minAge := 90*time.Second, 2*time.Hour

	svc1 := NewService(NewNormalizer(future, minAge))
	svc1.norm.SetClock(func() time.Time { return base })
	p := svc1.Policy()
	if time.Duration(p.MaxFutureSkew) != future || time.Duration(p.MinAge) != minAge {
		t.Fatalf("导出口径异常: %+v", p)
	}

	// 原进程对 4 条边界记录的结论。
	probe := func(s *Service) map[string]event.Reason {
		out := map[string]event.Reason{}
		for name, raw := range map[string]string{
			"future_exact": tpRaw(future),
			"future_over":  tpRaw(future + time.Nanosecond),
			"old_exact":    tpRaw(-minAge),
			"old_over":     tpRaw(-minAge - time.Nanosecond),
		} {
			r := s.Ingest(raw)
			if !r.Accepted() {
				out[name] = r.Rejected.Reason
			}
		}
		return out
	}
	want := probe(NewServiceWithClock(t, future, minAge, base))
	if want["future_exact"] != "" || want["future_over"] != event.ReasonFutureEvent ||
		want["old_exact"] != "" || want["old_over"] != event.ReasonTooOld {
		t.Fatalf("参照边界结论异常: %+v", want)
	}

	// 新进程：刻意用默认 1h/0 构造，再强制套用快照口径。
	svc2 := NewService(NewNormalizer(time.Hour, 0))
	svc2.norm.SetClock(func() time.Time { return base })
	if err := svc2.ApplyTimePolicy(p); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := svc2.Policy(); time.Duration(got.MaxFutureSkew) != future ||
		time.Duration(got.MinAge) != minAge {
		t.Fatalf("应用后口径异常: %+v", got)
	}
	if got := probe(svc2); !reasonMapsEqual(got, want) {
		t.Fatalf("恢复后边界结论与原进程不一致:\nwant=%v\ngot =%v", want, got)
	}
	t.Logf("非默认口径恢复后边界逐条一致: %+v", want)
}

// TestApplyTimePolicyRejectsInvalid 负值口径必须明确拒绝。
func TestApplyTimePolicyRejectsInvalid(t *testing.T) {
	svc := NewService(nil)
	if err := svc.ApplyTimePolicy(snapshot.TimePolicy{MaxFutureSkew: -1}); !errors.Is(err, snapshot.ErrInvalidTimePolicy) {
		t.Fatalf("负未来容忍应 ErrInvalidTimePolicy, got %v", err)
	}
	if err := svc.ApplyTimePolicy(snapshot.TimePolicy{MinAge: -1}); !errors.Is(err, snapshot.ErrInvalidTimePolicy) {
		t.Fatalf("负回溯年龄应 ErrInvalidTimePolicy, got %v", err)
	}
}

// NewServiceWithClock 构造一个带固定时钟的服务（测试辅助）。
func NewServiceWithClock(t *testing.T, future, minAge time.Duration, base time.Time) *Service {
	t.Helper()
	n := NewNormalizer(future, minAge)
	n.SetClock(func() time.Time { return base })
	return NewService(n)
}

func reasonMapsEqual(a, b map[string]event.Reason) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
