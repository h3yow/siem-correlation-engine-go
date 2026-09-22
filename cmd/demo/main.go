// Command demo 在本地端到端运行安全事件关联检测引擎：
// 生成模拟日志流（含乱序/重复/畸形） -> 并发摄取归一化 -> 滑动窗口关联
// -> 高频抑制 -> 运行期规则热更新，打印一致且可解释的结论。
//
// 运行：
//
//	go run ./cmd/demo
package main

import (
	"fmt"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/datagen"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

func main() {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	gen := datagen.New(20260923)

	records := gen.GenerateBruteForce(base.UnixMilli())
	records = datagen.Shuffle(records, 42) // 模拟乱序到达
	malformed := gen.GenerateMalformed(base.UnixMilli())

	var raws []string
	for _, r := range records {
		raws = append(raws, r.Raw)
	}
	for _, r := range malformed {
		raws = append(raws, r.Raw)
	}

	fmt.Println("================ 1) 并发乱序摄取（多格式归一化） ================")
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	ingested := svc.IngestConcurrent(raws)

	var evs []event.Event
	rejected := map[event.Reason]int{}
	for _, ir := range ingested {
		if ir.Accepted() {
			evs = append(evs, ir.Event)
		} else {
			rejected[ir.Rejected.Reason]++
			fmt.Printf("[拒绝] reason=%-18s %s\n", ir.Rejected.Reason, ir.Rejected.Detail)
		}
	}
	accepted, duplicated := svc.Stats()
	fmt.Printf("摄取统计: 接受=%d (去重表=%d) 重复=%d 拒绝分布=%v\n\n", len(evs), accepted, duplicated, rejected)

	fmt.Println("================ 2) 滑动窗口关联检测 ================")
	cfg := rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       10 * time.Minute,
		MaxOccurrences: 20,
	}
	eng := correlate.NewEngine(cfg, time.Minute)
	r := rule.Rule{
		ID:       "ssh-brute-force",
		Name:     "SSH 暴力破解（5 次失败后锁定）",
		Severity: event.SeverityHigh,
		Window:   10 * time.Second,
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
	if err := eng.UpsertRule(r, 1); err != nil {
		panic(err)
	}

	// 处理前半批事件后做一次运行期规则热更新（窗口放宽到 30s，版本 v2）。
	half := len(evs) / 2
	r1 := eng.ProcessBatch(evs[:half])
	fmt.Printf("热更新前(v1)处理 %d 个事件，产出 %d 条告警结论\n", half, len(r1.Alerts))
	if err := eng.UpsertRule(func() rule.Rule {
		u := r
		u.Window = 30 * time.Second
		return u
	}(), 2); err != nil {
		panic(err)
	}
	r2 := eng.ProcessBatch(evs[half:])
	fmt.Printf("热更新后(v2)处理剩余事件，产出 %d 条告警结论\n\n", len(r2.Alerts))

	printAlerts(append(r1.Alerts, r2.Alerts...))

	fmt.Println("================ 3) 窗口状态（判定依据可解释） ================")
	fmt.Println(eng.DumpState())

	fmt.Println("================ 4) 同一批历史事件以新乱序重放 ================")
	eng2 := correlate.NewEngine(cfg, time.Minute)
	_ = eng2.UpsertRule(r, 1)
	replay := eng2.ProcessBatchShuffled(evs, 999)
	refired := 0
	for _, a := range replay.Alerts {
		if a.Kind == alert.KindFired {
			refired++
		}
	}
	fmt.Printf("重放产出 Fired=%d（全新引擎预期 1，指纹与首轮相同）\n", refired)
}

func printAlerts(as []alert.Alert) {
	for _, a := range as {
		switch a.Kind {
		case alert.KindFired:
			fmt.Printf("[FIRED]      rule=%s v%d severity=%s agg=%s\n", a.RuleID, a.RuleVersion, a.Severity, a.AggregateKey)
		case alert.KindSuppressed:
			fmt.Printf("[SUPPRESSED] rule=%s v%d agg=%s occurrence=%d suppressed_by=%s\n",
				a.RuleID, a.RuleVersion, a.AggregateKey, a.OccurrenceCnt, a.SuppressedBy)
		}
		fmt.Printf("    判定: %s\n", a.Reason)
		fmt.Printf("    证据: %v  时间范围: %s ~ %s\n\n",
			a.EventIDs(), a.FirstEventAt.Format(time.RFC3339), a.LastEventAt.Format(time.RFC3339))
	}
}
