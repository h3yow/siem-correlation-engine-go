package snapshot_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

var testBase = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

type testEnv struct {
	svc      *ingest.Service
	eng      *correlate.Engine
	mu       sync.Mutex
	accepted []event.Event
	alerts   []alert.Alert
	rejected []event.RejectedRecord
}

func testCfg() rule.SuppressionConfig {
	return rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       5 * time.Minute,
		MaxOccurrences: 20,
	}
}

func newTestEnv(allowedLateness time.Duration) *testEnv {
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return testBase.Add(24 * time.Hour) })
	svc := ingest.NewService(norm)
	eng := correlate.NewEngine(testCfg(), allowedLateness)
	return &testEnv{svc: svc, eng: eng}
}

// mkTestEvent 构造 ID 确定的事件（内容哈希派生，全序清晰）。
func mkTestEvent(at time.Time, srcIP, evType, action, user string) event.Event {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s|%s", at.UnixNano(), srcIP, evType, action, user)))
	id := "evt-" + hex.EncodeToString(h[:8])
	return event.Event{
		ID:         id,
		OccurredAt: at,
		Source:     "sshd",
		EventType:  evType,
		SrcIP:      srcIP,
		User:       user,
		Action:     action,
		SrcHost:    "web-01",
	}
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

// feed 向环境投递一批事件（经摄取幂等层 + 引擎），累计结论。
func (env *testEnv) feed(t *testing.T, evs []event.Event) {
	t.Helper()
	env.mu.Lock()
	defer env.mu.Unlock()
	for _, ev := range evs {
		// 事件由上层直接给出，但仍走一次幂等层（以规范化 Raw 作为去重键），
		// 从而与真实链路一致地验证跨重启 duplicate 语义。
		if env.svc != nil {
			if r := env.svc.Ingest(eventRaw(ev)); !r.Accepted() {
				env.rejected = append(env.rejected, *r.Rejected)
				continue
			}
		}
		env.accepted = append(env.accepted, ev)
		alerts, rj := env.eng.ProcessEvent(ev)
		env.alerts = append(env.alerts, alerts...)
		if rj != nil {
			env.rejected = append(env.rejected, *rj)
		}
	}
}

// eventRaw 生成一条可被 keyvalue 解析器确定性归一、且与 ev 字段一致的记录。
func eventRaw(ev event.Event) string {
	return fmt.Sprintf(
		`timestamp=%q source=%s event_type=%s src_ip=%s user=%s action=%s`,
		ev.OccurredAt.UTC().Format(time.RFC3339Nano), ev.Source, ev.EventType,
		ev.SrcIP, ev.User, ev.Action)
}

// restart 导出快照并用其在新进程（新 env）中恢复，返回恢复后的环境。
// 结论历史（alerts/rejected）不随快照迁移，由 envB 重新累积以便对比。
func (env *testEnv) restart(t *testing.T) *testEnv {
	t.Helper()
	snap := snapshot.Export(env.svc, env.eng)
	data, err := snap.Encode()
	if err != nil {
		t.Fatalf("encode snapshot: %v", err)
	}
	got, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	svc2, eng2, err := got.Restore(snapshot.WithClock(func() time.Time {
		return testBase.Add(24 * time.Hour)
	}))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	return &testEnv{svc: svc2, eng: eng2}
}

// conclusion 是对全部累计结论的确定性签名：重启前后必须完全一致。
func (env *testEnv) conclusion() string {
	env.mu.Lock()
	defer env.mu.Unlock()
	var b strings.Builder
	b.WriteString("alerts:")
	as := append([]alert.Alert{}, env.alerts...)
	sort.SliceStable(as, func(i, j int) bool {
		if !as[i].FirstEventAt.Equal(as[j].FirstEventAt) {
			return as[i].FirstEventAt.Before(as[j].FirstEventAt)
		}
		if as[i].RuleID != as[j].RuleID {
			return as[i].RuleID < as[j].RuleID
		}
		if as[i].DedupKey != as[j].DedupKey {
			return as[i].DedupKey < as[j].DedupKey
		}
		return as[i].Kind < as[j].Kind
	})
	for _, a := range as {
		fmt.Fprintf(&b, "%s/%s/v%d/%s/occ%d;", a.Kind, a.RuleID, a.RuleVersion, a.DedupKey, a.OccurrenceCnt)
	}
	b.WriteString("|reject:")
	rs := append([]event.RejectedRecord{}, env.rejected...)
	sort.SliceStable(rs, func(i, j int) bool {
		if rs[i].Reason != rs[j].Reason {
			return rs[i].Reason < rs[j].Reason
		}
		return rs[i].Raw < rs[j].Raw
	})
	for _, r := range rs {
		fmt.Fprintf(&b, "%s/%s;", r.Reason, r.Raw)
	}
	return b.String()
}

func countFired(as []alert.Alert) int {
	n := 0
	for _, a := range as {
		if a.Kind == alert.KindFired {
			n++
		}
	}
	return n
}

func ipStr(i int) string {
	return fmt.Sprintf("10.10.%d.%d", i/10, i%10)
}
