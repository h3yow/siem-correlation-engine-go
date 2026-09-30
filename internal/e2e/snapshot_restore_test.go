package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/datagen"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

// ingestAll 并发摄取全部原始记录，返回接受事件与"原因 -> 次数"的拒绝分布。
func ingestAll(t *testing.T, raws []string, base time.Time, svc *ingest.Service) ([]event.Event, map[event.Reason]int) {
	t.Helper()
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
	return evs, reasons
}

func restoreCfg() rule.SuppressionConfig {
	return rule.SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       10 * time.Minute,
		MaxOccurrences: 20,
	}
}

// runReference 参照路径：单进程绑定摄取服务，处理前半 -> 后半 -> 重放重复。
func runReference(t *testing.T, evs []event.Event, replayRaws []string, base time.Time) string {
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)

	eng := correlate.NewEngine(restoreCfg(), time.Minute)
	eng.BindIngestService(svc)
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatal(err)
	}
	half := len(evs) / 2
	r1 := eng.ProcessBatch(evs[:half])

	// 在中途做一次规则热更新（v2），快照必须捕获该版本。
	if err := eng.UpsertRule(bruteForceRule(30*time.Second, 2), 2); err != nil {
		t.Fatal(err)
	}
	r2 := eng.ProcessBatch(evs[half:])

	// 重启后继续喂的事件：乱序到达 + 重复原始记录投递。
	repEvs, repRej := ingestAll(t, replayRaws, base, svc)
	r3 := eng.ProcessBatch(repEvs)

	return fullSignature(append(append(r1.Alerts, r2.Alerts...), r3.Alerts...), repRej)
}

// runRestored 重启路径：处理前半并热更新后导出快照，新进程恢复，
// 再喂后半与乱序/重复事件。
func runRestored(t *testing.T, evs []event.Event, replayRaws []string, base time.Time) string {
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)

	eng := correlate.NewEngine(restoreCfg(), time.Minute)
	eng.BindIngestService(svc)
	eng.SetEngineID("e2e-restore-demo")
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatal(err)
	}
	half := len(evs) / 2
	r1 := eng.ProcessBatch(evs[:half])
	if err := eng.UpsertRule(bruteForceRule(30*time.Second, 2), 2); err != nil {
		t.Fatal(err)
	}

	// 导出到真实磁盘文件（原子落盘），模拟进程退出。
	path := filepath.Join(t.TempDir(), "engine.snap.json")
	if err := eng.SaveSnapshot(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// 新进程：全新摄取服务，从快照恢复（连幂等去重表一起）。
	norm2 := ingest.NewNormalizer(time.Hour, 0)
	norm2.SetClock(func() time.Time { return base })
	svc2 := ingest.NewService(norm2)
	restored, err := correlate.LoadSnapshotFromFile(path, svc2)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if restored.EngineID() != "e2e-restore-demo" {
		t.Fatalf("engine id lost across restore")
	}

	r2 := restored.ProcessBatch(evs[half:])
	repEvs, repRej := ingestAll(t, replayRaws, base, svc2)
	r3 := restored.ProcessBatch(repEvs)

	return fullSignature(append(append(r1.Alerts, r2.Alerts...), r3.Alerts...), repRej)
}

// fullSignature 对告警身份（种类/规则/版本/指纹/聚合身份/计数）与重启后
// 拒绝分布同时签名，逐字节比较"从未重启"与"导出恢复"两条路径。
func fullSignature(as []alert.Alert, repRej map[event.Reason]int) string {
	s := "alerts:"
	for _, a := range as {
		s += fmt.Sprintf("%s:%s:v%d:%s:%s:occ%d:%s;",
			a.Kind, a.RuleID, a.RuleVersion, a.DedupKey,
			a.AggregateKey, a.OccurrenceCnt, a.SuppressedBy)
	}
	s += "|rep_reject:"
	for _, r := range []event.Reason{
		event.ReasonDuplicate, event.ReasonMalformed, event.ReasonTooOld,
		event.ReasonFutureEvent, event.Reason("too_late"),
	} {
		s += string(r) + "=" + fmt.Sprintf("%d,", repRej[r])
	}
	return s
}

// TestEndToEndSnapshotRestoreEquivalent 是端到端主测试：真实多格式混合流
// （乱序+畸形）在序列中途导出/恢复，恢复边界跨有乱序与重复投递，
// 断言两条路径的告警身份与拒绝分布逐字节一致（不重不漏）。
func TestEndToEndSnapshotRestoreEquivalent(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	gen := datagen.New(42)
	records := datagen.Shuffle(gen.GenerateBruteForce(base.UnixMilli()), 42)
	malformed := gen.GenerateMalformed(base.UnixMilli())

	var raws []string
	for _, r := range records {
		raws = append(raws, r.Raw)
	}
	// 第一次摄取（参照与重启路径共用相同输入），用独立服务先取出 evs。
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	seedSvc := ingest.NewService(norm)
	evs, _ := ingestAll(t, raws, base, seedSvc)

	// 重启后继续喂的输入：对前若干条原始记录做确定性乱序重排，并混入
	// 畸形样本——它们在恢复后到达，跨恢复边界。洗牌在 RawRecord 层进行
	// （datagen.Shuffle 的入参类型）。
	replayRecords := datagen.Shuffle(append([]datagen.RawRecord{}, records...), 2026)
	if len(replayRecords) > 8 {
		replayRecords = replayRecords[:8]
	}
	var replayRaws []string
	for _, r := range replayRecords {
		replayRaws = append(replayRaws, r.Raw)
	}
	for _, r := range malformed {
		replayRaws = append(replayRaws, r.Raw)
	}

	ref := runReference(t, evs, replayRaws, base)
	got := runRestored(t, evs, replayRaws, base)
	t.Logf("参照(未重启): %s", ref)
	t.Logf("快照/恢复  : %s", got)
	if ref != got {
		t.Fatalf("跨重启结论不一致:\nref=%s\ngot=%s", ref, got)
	}
	t.Log("端到端：乱序+重复+畸形跨过恢复边界，告警身份与拒绝分布逐字节一致")
}

// TestEndToEndSnapshotFileIsVersioned 端到端落盘文件必须带版本与校验和。
func TestEndToEndSnapshotFileIsVersioned(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	norm := ingest.NewNormalizer(time.Hour, 0)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	eng := correlate.NewEngine(restoreCfg(), time.Minute)
	eng.BindIngestService(svc)
	_ = eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1)

	gen := datagen.New(7)
	records := gen.GenerateBruteForce(base.UnixMilli())
	evs, _ := ingestAll(t, rawsOf(records), base, svc)
	eng.ProcessBatch(evs)

	path := filepath.Join(t.TempDir(), "e2e.snap.json")
	if err := eng.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, want := range []string{"\"format_version\": 1", "\"checksum\":", "\"rules\":", "\"watermark\":", "\"ingest_seen\":", "\"aggregate_by\":", "\"version\": 1"} {
		if !strings.Contains(s, want) {
			t.Fatalf("snapshot file missing %s", want)
		}
	}
}

func rawsOf(rs []datagen.RawRecord) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Raw
	}
	return out
}
