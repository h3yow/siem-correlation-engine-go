package alert

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

func TestFingerprintOrderIndependent(t *testing.T) {
	tm := time.Now()
	mk := func(ids ...string) []*event.Event {
		out := make([]*event.Event, len(ids))
		for i, id := range ids {
			out[i] = &event.Event{ID: id, Timestamp: tm.Add(time.Duration(i) * time.Second)}
		}
		return out
	}
	chain := mk("a", "b", "c")
	fp1 := FingerprintFor("r1", "p", chain)
	fp2 := FingerprintFor("r1", "p", []*event.Event{chain[2], chain[0], chain[1]})
	if fp1 != fp2 {
		t.Fatal("指纹必须与证据顺序无关")
	}
	fp3 := FingerprintFor("r1", "other", chain)
	if fp1 == fp3 {
		t.Fatal("不同分区指纹必须不同")
	}
	if fp4 := FingerprintFor("r2", "p", chain); fp4 == fp1 {
		t.Fatal("不同规则指纹必须不同")
	}
	t.Logf("稳定指纹=%s", fp1)
}

func TestHighestSeverity(t *testing.T) {
	evs := []*event.Event{{Severity: event.SeverityInfo}, {Severity: event.SeverityCritical}, {Severity: event.SeverityMedium}}
	if got := HighestSeverity(evs); got != event.SeverityCritical {
		t.Fatalf("最高级别应为 critical，实际 %s", got)
	}
}
