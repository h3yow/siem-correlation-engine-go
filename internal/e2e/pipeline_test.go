// Package e2e_test 端到端验证：本地生成的混合日志流在乱序、并发、
// 畸形输入与规则变更下，告警结论一致且可解释。
package e2e_test

import (
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/datagen"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

var versionToken = regexp.MustCompile(`v[0-9]+:`)

func bruteForceRule(win time.Duration, version int) rule.Rule {
	return rule.Rule{
		ID:       "ssh-brute-force",
		Name:     "SSH 暴力破解（多源格式）",
		Severity: event.SeverityHigh,
		Window:   win,
		GroupBy:  "src_ip",
		Pattern: []rule.Match{
			{EventType: "auth.failure"},
			{EventType: "auth.failure"},
			{EventType: "auth.failure"},
			{EventType: "auth.failure"},
			{EventType: "auth.failure"},
			{EventType: "auth.locked"},
		},
	}
}

// pipeline 跑一遍完整链路，返回用于跨轮次比较的结论签名。
func pipeline(t *testing.T, seed int64, updateRule bool) string {
	t.Helper()
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	baseMs := base.UnixMilli()

	gen := datagen.New(seed)
	records := gen.GenerateBruteForce(baseMs)
	malformed := gen.GenerateMalformed(baseMs)

	// 确定性乱序：模拟真实环境中的乱序到达。
	records = datagen.Shuffle(records, seed)

	var raws []string
	for _, r := range records {
		raws = append(raws, r.Raw)
	}
	for _, r := range malformed {
		raws = append(raws, r.Raw)
	}

	// 并发摄取（注入固定时钟：基准 2026-09-23 12:00，1h skew 使未来样本被拒）。
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	ingested := svc.IngestConcurrent(raws)

	var evs []event.Event
	reasons := map[event.Reason]int{}
	for _, ir := range ingested {
		if ir.Accepted() {
			evs = append(evs, ir.Event)
		} else {
			reasons[ir.Rejected.Reason]++
		}
	}
	t.Logf("[seed=%d] 摄取: 接受=%d 拒绝分布=%v", seed, len(evs), reasons)

	cfg := rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       10 * time.Minute,
		MaxOccurrences: 20,
	}
	eng := correlate.NewEngine(cfg, time.Minute)
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if updateRule {
		// 在处理中途更新规则（放宽窗口到 30s，版本 2），窗口状态必须保留。
		half := len(evs) / 2
		r1 := eng.ProcessBatch(evs[:half])
		if err := eng.UpsertRule(bruteForceRule(30*time.Second, 2), 2); err != nil {
			t.Fatalf("update: %v", err)
		}
		r2 := eng.ProcessBatch(evs[half:])
		// 合并告警用于签名（仅取关键身份字段）。
		return signature(append(r1.Alerts, r2.Alerts...), reasons)
	}

	res := eng.ProcessBatch(evs)
	for _, a := range res.Alerts {
		verb := "FIRED     "
		if a.Kind == alert.KindSuppressed {
			verb = "SUPPRESSED"
		}
		t.Logf("%s rule=%s v%d agg=%s occ=%d seq=%s", verb, a.RuleID, a.RuleVersion,
			a.AggregateKey, a.OccurrenceCnt, a.DedupKey)
	}
	t.Log("\n" + eng.DumpState())
	return signature(res.Alerts, reasons)
}

func signature(as []alert.Alert, reasons map[event.Reason]int) string {
	s := "reject:"
	for _, r := range []event.Reason{
		event.ReasonEmpty, event.ReasonUnsupportedFormat, event.ReasonMalformed,
		event.ReasonMissingTimestamp, event.ReasonBadTimestamp,
		event.ReasonMissingEventTime, event.ReasonFutureEvent, event.ReasonDuplicate,
	} {
		s += fmt.Sprintf("%s=%d,", r, reasons[r])
	}
	s += "|alerts:"
	for _, a := range as {
		s += fmt.Sprintf("%s:%s:v%d:%s:occ%d;", a.Kind, a.RuleID, a.RuleVersion, a.DedupKey, a.OccurrenceCnt)
	}
	return s
}

func TestEndToEndConsistencyAcrossOrderingAndConcurrency(t *testing.T) {
	sigs := map[string]int{}
	for _, seed := range []int64{1, 7, 42, 100, 2026} {
		s := pipeline(t, seed, false)
		sigs[s]++
		t.Logf("[seed=%d] 结论签名:\n%s\n", seed, s)
	}
	if len(sigs) != 1 {
		t.Fatalf("不同乱序/并发轮次结论不一致，出现 %d 种签名", len(sigs))
	}
	t.Log("5 个不同乱序种子下，告警结论与拒绝分布完全一致")
}

func TestEndToEndRuleUpdateReproducible(t *testing.T) {
	without := pipeline(t, 42, false)
	with := pipeline(t, 42, true)
	// 放宽窗口不应改变本批数据的命中身份（所有事件本就在 10s 内），
	// 区别只允许体现在 RuleVersion 上；去掉版本标记后必须一致。
	stripVersion := func(s string) string { return versionToken.ReplaceAllString(s, "") }
	if stripVersion(without) != stripVersion(with) {
		t.Fatalf("规则更新前后历史判定不可复现:\n无更新=%s\n有更新=%s", without, with)
	}
	t.Log("规则变更前后，对同一批历史事件的判定身份一致（仅 RuleVersion 变化），可复现")
}
