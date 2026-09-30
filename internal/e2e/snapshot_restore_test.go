package e2e_test

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/datagen"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// runPipeline 用给定原始记录跑完整链路（并发摄取 -> 关联检测）。
//
// restartAfter > 0 时，在处理完前 restartAfter 条记录后导出快照并用其在
// 新进程恢复，再处理剩余记录。返回全链路结论签名（告警身份 + 拒绝分布）。
func runPipeline(t *testing.T, rawRecords []datagen.RawRecord, restartAfter int) string {
	t.Helper()
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	cfg := rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       10 * time.Minute,
		MaxOccurrences: 20,
	}
	eng := correlate.NewEngine(cfg, time.Minute)
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// 记录拒绝分布：按原始内容逐批摄取（保持与流水线同样的顺序），
	// 事件则逐条喂给引擎，结论累计。
	var allAlerts []alertLite
	reasons := map[event.Reason]int{}

	drive := func(recs []datagen.RawRecord) {
		for _, rec := range recs {
			res := svc.Ingest(rec.Raw)
			if !res.Accepted() {
				reasons[res.Rejected.Reason]++
				continue
			}
			alerts, rj := eng.ProcessEvent(res.Event)
			for _, a := range alerts {
				allAlerts = append(allAlerts, alertLite{
					kind: a.Kind, rule: a.RuleID, v: a.RuleVersion,
					fp: a.DedupKey, occ: a.OccurrenceCnt,
				})
			}
			if rj != nil {
				reasons[rj.Reason]++
			}
		}
	}

	if restartAfter > 0 {
		drive(rawRecords[:restartAfter])
		snap := snapshot.Export(svc, eng)
		data, err := snap.Encode()
		if err != nil {
			t.Fatalf("snapshot encode: %v", err)
		}
		got, err := snapshot.Decode(data)
		if err != nil {
			t.Fatalf("snapshot decode: %v", err)
		}
		svc, eng, err = got.Restore(snapshot.WithClock(func() time.Time { return base }))
		if err != nil {
			t.Fatalf("snapshot restore: %v", err)
		}
		drive(rawRecords[restartAfter:])
	} else {
		drive(rawRecords)
	}

	return liteSignature(allAlerts, reasons)
}

type alertLite struct {
	kind alert.Kind
	rule string
	v    int
	fp   string
	occ  int
}

func liteSignature(as []alertLite, reasons map[event.Reason]int) string {
	s := "reject:"
	for _, r := range []event.Reason{
		event.ReasonEmpty, event.ReasonUnsupportedFormat, event.ReasonMalformed,
		event.ReasonMissingTimestamp, event.ReasonBadTimestamp,
		event.ReasonMissingEventTime, event.ReasonFutureEvent, event.ReasonDuplicate,
		event.Reason("too_late"),
	} {
		s += string(r) + "=" + itoa(reasons[r]) + ","
	}
	s += "|alerts:"
	for _, a := range as {
		s += string(a.kind) + ":" + a.rule + ":v" + itoa(a.v) + ":" + a.fp + ":occ" + itoa(a.occ) + ";"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	b := []byte{}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestEndToEndSnapshotRestartMatchesNoRestart 真实混合流（多格式 + 乱序 +
// 重复 + 畸形）在多个不同恢复点重启后，结论签名必须与"从不重启"完全一致。
func TestEndToEndSnapshotRestartMatchesNoRestart(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	gen := datagen.New(20260923)
	records := gen.GenerateBruteForce(base.UnixMilli())
	records = datagen.Shuffle(records, 42)
	records = append(records, gen.GenerateMalformed(base.UnixMilli())...)

	noRestart := runPipeline(t, records, 0)
	t.Logf("[不重启] 签名:\n%s", noRestart)

	for _, at := range []int{1, len(records) / 3, len(records) / 2, len(records) - 1} {
		got := runPipeline(t, records, at)
		if got != noRestart {
			t.Fatalf("恢复点=%d 结论与不重启不一致:\n got=%s\nwant=%s", at, got, noRestart)
		}
		t.Logf("[恢复点=%d] 结论与不重启完全一致", at)
	}
}

// runPipelineWithRuleUpdate 与 runPipeline 相同，但在 updateAfter 条记录处
// 把规则窗口放宽到 30s 并升级到 v2（模拟运行期规则热更新）。
func runPipelineWithRuleUpdate(t *testing.T, rawRecords []datagen.RawRecord, restartAfter, updateAfter int) string {
	t.Helper()
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	cfg := rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       10 * time.Minute,
		MaxOccurrences: 20,
	}
	eng := correlate.NewEngine(cfg, time.Minute)
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	var allAlerts []alertLite
	reasons := map[event.Reason]int{}
	drive := func(recs []datagen.RawRecord) {
		for _, rec := range recs {
			res := svc.Ingest(rec.Raw)
			if !res.Accepted() {
				reasons[res.Rejected.Reason]++
				continue
			}
			alerts, rj := eng.ProcessEvent(res.Event)
			for _, a := range alerts {
				allAlerts = append(allAlerts, alertLite{
					kind: a.Kind, rule: a.RuleID, v: a.RuleVersion,
					fp: a.DedupKey, occ: a.OccurrenceCnt,
				})
			}
			if rj != nil {
				reasons[rj.Reason]++
			}
		}
	}

	// 计算不重叠的分段边界：updateAfter 与 restartAfter（取排序后的唯一点）。
	cuts := []int{}
	for _, c := range []int{updateAfter, restartAfter} {
		if c > 0 {
			cuts = append(cuts, c)
		}
	}
	sortInts(cuts)
	cuts = dedupInts(cuts)

	prev := 0
	for _, cut := range cuts {
		drive(rawRecords[prev:cut])
		switch cut {
		case updateAfter:
			if err := eng.UpsertRule(bruteForceRule(30*time.Second, 2), 2); err != nil {
				t.Fatalf("rule update: %v", err)
			}
		}
		if cut == restartAfter {
			snap := snapshot.Export(svc, eng)
			data, err := snap.Encode()
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := snapshot.Decode(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			svc, eng, err = got.Restore(snapshot.WithClock(func() time.Time { return base }))
			if err != nil {
				t.Fatalf("restore: %v", err)
			}
		}
		prev = cut
	}
	drive(rawRecords[prev:])
	return liteSignature(allAlerts, reasons)
}

func sortInts(xs []int) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && xs[j-1] > xs[j]; j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}

func dedupInts(xs []int) []int {
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// TestEndToEndRuleUpdateAcrossRestart 热更新在重启前生效，重启后继续喂事件：
// 最终结论（含规则版本）必须与"不重启、只做同样热更新"一致。
func TestEndToEndRuleUpdateAcrossRestart(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	gen := datagen.New(20260923)
	records := gen.GenerateBruteForce(base.UnixMilli())
	records = datagen.Shuffle(records, 42)
	records = append(records, gen.GenerateMalformed(base.UnixMilli())...)

	// 更新点在 1/3 处；重启点在 2/3 处（即重启时规则已经是 v2）。
	updateAt := len(records) / 3
	restartAt := 2 * len(records) / 3
	withoutRestart := runPipelineWithRuleUpdate(t, records, 0, updateAt)
	withRestart := runPipelineWithRuleUpdate(t, records, restartAt, updateAt)
	if withRestart != withoutRestart {
		t.Fatalf("热更新后跨重启结论不一致:\n 重启=%s\n不重启=%s", withRestart, withoutRestart)
	}
	t.Log("规则热更新（v1->v2）发生在重启前，恢复后继续处理：结论与不重启逐字一致")
}
