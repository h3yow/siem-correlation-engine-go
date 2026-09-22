package e2e_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/datagen"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

// TestConcurrentRunsConverge 模拟多个 goroutine 各自并发摄取同一批真实日志
// 并各自驱动一个引擎，断言所有引擎的告警身份与拒绝分布完全收敛。
func TestConcurrentRunsConverge(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	gen := datagen.New(7)
	records := gen.GenerateBruteForce(base.UnixMilli())
	records = append(records, gen.GenerateMalformed(base.UnixMilli())...)
	raws := make([]string, len(records))
	for i, r := range records {
		raws[i] = r.Raw
	}

	ruleDef := bruteForceRule(10*time.Second, 1)
	run := func(seed int64) string {
		shuffled := datagen.Shuffle(records, seed)
		norm := ingest.NewNormalizer(time.Hour, 0)
		norm.SetClock(func() time.Time { return base })
		svc := ingest.NewService(norm)
		results := svc.IngestConcurrent(toRawStrings(shuffled))

		var evs []event.Event
		reasons := map[event.Reason]int{}
		for _, ir := range results {
			if ir.Accepted() {
				evs = append(evs, ir.Event)
			} else {
				reasons[ir.Rejected.Reason]++
			}
		}
		cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Hour, MaxOccurrences: 10}
		eng := correlate.NewEngine(cfg, time.Minute)
		_ = eng.UpsertRule(ruleDef, 1)
		res := eng.ProcessBatch(evs)
		return signature(res.Alerts, reasons)
	}

	sigs := sync.Map{}
	var wg sync.WaitGroup
	for i := int64(0); i < 12; i++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			sigs.Store(run(seed+1), struct{}{})
		}(i)
	}
	wg.Wait()

	n := 0
	var first string
	sigs.Range(func(k, _ any) bool {
		n++
		if first == "" {
			first = k.(string)
		}
		return true
	})
	if n != 1 {
		t.Fatalf("并发各引擎结论未收敛，出现 %d 种签名", n)
	}
	fmt.Println("12 个并发独立引擎（各自并发摄取+乱序）结论完全收敛为同一签名")
}

func toRawStrings(rs []datagen.RawRecord) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Raw
	}
	return out
}
