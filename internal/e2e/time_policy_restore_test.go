// Package e2e_test 的本文件专门覆盖"非默认事件时间口径"的跨进程恢复：
//
//	服务按业务把 MaxFutureSkew（未来容忍）/ MinAge（最早回溯）调成了
//	非默认值，在运行中途导出快照；新进程用另一套（默认）口径构造摄取服务
//	再从快照恢复。恢复后的 future_event / too_old 边界判定必须与"从未重启"
//	逐条一致——包括刚好落在容忍/回溯边界内、等于边界、刚好超出的记录。
package e2e_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// timePolicy 是本用例采用的非默认业务口径（刻意远离默认 1h/0）。
var (
	tpFuture = 90 * time.Second
	tpMinAge = 2 * time.Hour
)

// tpJSON 构造一条 JSON 记录；marker 保证每条原始内容唯一，避免撞幂等去重。
func tpJSON(at time.Time, ip, etype, action, marker string) string {
	return fmt.Sprintf(
		`{"timestamp":%q,"source":"sshd","event_type":%q,"action":%q,"src_ip":%q,"user":"root","marker":%q}`,
		at.UTC().Format(time.RFC3339Nano), etype, action, ip, marker)
}

// tpOutcome 汇总一条路径（未重启 / 导出恢复）重启后阶段的全部结论。
type tpOutcome struct {
	accept   int
	reasons  map[event.Reason]int
	alertSig string
	fired    int
}

// tpSignature 对接受/拒绝分布与告警身份同时签名，供两条路径逐字节比对。
func tpSignature(o tpOutcome) string {
	s := fmt.Sprintf("accept=%d", o.accept)
	for _, r := range []event.Reason{
		event.ReasonFutureEvent, event.ReasonTooOld, event.ReasonDuplicate,
		event.ReasonMalformed, event.Reason("too_late"),
	} {
		s += fmt.Sprintf(";%s=%d", r, o.reasons[r])
	}
	return s + "|alerts=" + o.alertSig + fmt.Sprintf("|fired=%d", o.fired)
}

func tpCollect(t *testing.T, raws []string, svc *ingest.Service) ([]event.Event, map[event.Reason]int) {
	t.Helper()
	res := svc.IngestConcurrent(raws)
	var evs []event.Event
	reasons := map[event.Reason]int{}
	for _, ir := range res {
		if ir.Accepted() {
			evs = append(evs, ir.Event)
		} else {
			reasons[ir.Rejected.Reason]++
		}
	}
	return evs, reasons
}

func tpAlerts(as []alert.Alert) string {
	var s string
	for _, a := range as {
		s += fmt.Sprintf("%s:%s:v%d:%s:%s:occ%d;",
			a.Kind, a.RuleID, a.RuleVersion, a.DedupKey, a.AggregateKey, a.OccurrenceCnt)
	}
	return s
}

// tpPreRaws 重启前记录：一组完整的 5 失败 + 1 锁定（窗口 10s），
// 在重启前恰好产生 1 条 v1 告警。
func tpPreRaws(base time.Time) []string {
	ip := "10.0.0.1"
	var raws []string
	for i := 0; i < 5; i++ {
		raws = append(raws, tpJSON(base.Add(time.Duration(i)*time.Second),
			ip, "auth.failure", "login_failed", fmt.Sprintf("pre-f%d", i)))
	}
	raws = append(raws, tpJSON(base.Add(5*time.Second),
		ip, "auth.locked", "locked", "pre-lock"))
	return raws
}

// tpSeqRaws 是重启后凑齐的第二组完整序列（另一 src_ip），产生 1 条 v2 告警。
func tpSeqRaws(base time.Time) []string {
	ip := "10.0.0.2"
	// 落在墙钟前 30s 起的 6s 窗口内：既不碰未来/回溯边界，也晚于重启前
	// 水印（base+5s）减 allowed_lateness(1m)，不会被判 too_late。
	var seq []string
	for i := 0; i < 5; i++ {
		seq = append(seq, tpJSON(base.Add(-30*time.Second+time.Duration(i)*time.Second),
			ip, "auth.failure", "login_failed", fmt.Sprintf("post-f%d", i)))
	}
	seq = append(seq, tpJSON(base.Add(-30*time.Second+5*time.Second),
		ip, "auth.locked", "locked", "post-lock"))
	return seq
}

// tpBoundaryRaws 是刚好骑在未来/回溯边界上的 4 条记录：
// now+90s 恰好接受、now+91s 拒绝（future_event）；
// now-2h 恰好接受、now-2h-1ns 拒绝（too_old）。
func tpBoundaryRaws(base time.Time) []string {
	return []string{
		tpJSON(base.Add(tpFuture), "10.0.0.9", "net.connection", "allow", "future-exact"),
		tpJSON(base.Add(tpFuture+time.Nanosecond), "10.0.0.9", "net.connection", "allow", "future-over"),
		tpJSON(base.Add(-tpMinAge), "10.0.0.8", "net.connection", "allow", "old-exact"),
		tpJSON(base.Add(-tpMinAge-time.Nanosecond), "10.0.0.8", "net.connection", "allow", "old-over"),
	}
}

// runTPReference 参照路径：同一进程、非默认口径跑到底，中途也做规则热更新。
func runTPReference(t *testing.T, base time.Time, pre, seq, boundary []string) tpOutcome {
	norm := ingest.NewNormalizer(tpFuture, tpMinAge)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	eng := correlate.NewEngine(restoreCfg(), time.Minute)
	eng.BindIngestService(svc)
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatal(err)
	}

	preEvs, _ := tpCollect(t, pre, svc)
	r1 := eng.ProcessBatch(preEvs)
	if err := eng.UpsertRule(bruteForceRule(2*time.Minute, 2), 2); err != nil {
		t.Fatal(err)
	}

	// 重启后：先第二组序列（凑齐 v2 告警），再骑边界的未来/回溯记录。
	seqEvs, seqRej := tpCollect(t, seq, svc)
	r2 := eng.ProcessBatch(seqEvs)
	boundEvs, boundRej := tpCollect(t, boundary, svc)
	r3 := eng.ProcessBatch(boundEvs)

	reasons := map[event.Reason]int{}
	for k, v := range seqRej {
		reasons[k] += v
	}
	for k, v := range boundRej {
		reasons[k] += v
	}
	allAlerts := append(append(append([]alert.Alert{}, r1.Alerts...), r2.Alerts...), r3.Alerts...)
	return tpOutcome{
		accept:   len(seqEvs) + len(boundEvs),
		reasons:  reasons,
		alertSig: tpAlerts(allAlerts),
		fired:    len(firedList(allAlerts)),
	}
}

// runTPRestored 重启路径：非默认口径运行 + 热更新后导出；新进程刻意用
// "错误的默认口径"构造服务，再从快照恢复，断言快照口径强制生效。
func runTPRestored(t *testing.T, base time.Time, pre, seq, boundary []string) tpOutcome {
	norm := ingest.NewNormalizer(tpFuture, tpMinAge)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	eng := correlate.NewEngine(restoreCfg(), time.Minute)
	eng.BindIngestService(svc)
	eng.SetEngineID("tp-restore-demo")
	if err := eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1); err != nil {
		t.Fatal(err)
	}

	preEvs, _ := tpCollect(t, pre, svc)
	r1 := eng.ProcessBatch(preEvs)
	if err := eng.UpsertRule(bruteForceRule(2*time.Minute, 2), 2); err != nil {
		t.Fatal(err)
	}
	st := eng.ExportState()
	if st.TimePolicy == nil {
		t.Fatal("导出的快照必须携带事件时间口径")
	}
	if time.Duration(st.TimePolicy.MaxFutureSkew) != tpFuture ||
		time.Duration(st.TimePolicy.MinAge) != tpMinAge {
		t.Fatalf("快照口径与运行口径不一致: %+v", st.TimePolicy)
	}

	path := filepath.Join(t.TempDir(), "tp-engine.snap.json")
	if err := eng.SaveSnapshot(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// 新进程：刻意用默认 1h/0 口径构造（模拟调用方没有记住业务口径）。
	wrongNorm := ingest.NewNormalizer(time.Hour, 0)
	wrongNorm.SetClock(func() time.Time { return base })
	newSvc := ingest.NewService(wrongNorm)
	restored, err := correlate.LoadSnapshotFromFile(path, newSvc)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// 恢复后服务内的归一化口径必须已被快照口径覆盖。
	if got := newSvc.Policy(); time.Duration(got.MaxFutureSkew) != tpFuture ||
		time.Duration(got.MinAge) != tpMinAge {
		t.Fatalf("恢复后服务口径被调用方默认值污染: %+v", got)
	}
	if rp := restored.TimePolicy(); rp == nil ||
		time.Duration(rp.MaxFutureSkew) != tpFuture || time.Duration(rp.MinAge) != tpMinAge {
		t.Fatalf("恢复后引擎口径异常: %+v", rp)
	}

	seqEvs, seqRej := tpCollect(t, seq, newSvc)
	r2 := restored.ProcessBatch(seqEvs)
	boundEvs, boundRej := tpCollect(t, boundary, newSvc)
	r3 := restored.ProcessBatch(boundEvs)

	reasons := map[event.Reason]int{}
	for k, v := range seqRej {
		reasons[k] += v
	}
	for k, v := range boundRej {
		reasons[k] += v
	}
	allAlerts := append(append(append([]alert.Alert{}, r1.Alerts...), r2.Alerts...), r3.Alerts...)
	return tpOutcome{
		accept:   len(seqEvs) + len(boundEvs),
		reasons:  reasons,
		alertSig: tpAlerts(allAlerts),
		fired:    len(firedList(allAlerts)),
	}
}

func firedList(as []alert.Alert) []alert.Alert {
	var out []alert.Alert
	for _, a := range as {
		if a.Kind == alert.KindFired {
			out = append(out, a)
		}
	}
	return out
}

// TestEndToEndNonDefaultTimePolicySurvivesRestore 是本缺陷的主回归用例：
// 非默认时间口径下，运行中途（含规则热更新）导出快照、在新进程恢复后，
// 继续喂"刚好在未来/回溯边界内、等于边界、刚好超出"的记录，接受/拒绝
// 分布与告警结论必须与"从未重启"逐条一致。
func TestEndToEndNonDefaultTimePolicySurvivesRestore(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	pre := tpPreRaws(base)
	seq := tpSeqRaws(base)
	boundary := tpBoundaryRaws(base)

	ref := runTPReference(t, base, pre, seq, boundary)
	got := runTPRestored(t, base, pre, seq, boundary)

	t.Logf("业务口径: max_future_skew=%s min_age=%s", tpFuture, tpMinAge)
	t.Logf("参照(未重启) : %s", tpSignature(ref))
	t.Logf("快照/恢复   : %s", tpSignature(got))

	// 边界断言：恰好 2 条边界外记录被拒（future/old 各 1），其余接受。
	if ref.reasons[event.ReasonFutureEvent] != 1 || ref.reasons[event.ReasonTooOld] != 1 {
		t.Fatalf("参照边界拒绝数异常: future=%d old=%d",
			ref.reasons[event.ReasonFutureEvent], ref.reasons[event.ReasonTooOld])
	}
	if tpSignature(got) != tpSignature(ref) {
		t.Fatalf("非默认口径跨重启结论不一致:\nref=%s\ngot=%s",
			tpSignature(ref), tpSignature(got))
	}
	// 重启前 v1 + 重启后 v2 各一条 fired。
	if ref.fired != 2 || got.fired != 2 {
		t.Fatalf("两条路径都应有重启前/后各 1 条 fired: ref=%d got=%d", ref.fired, got.fired)
	}
	t.Log("非默认时间口径跨重启：边界内/等于边界接受、刚超出拒绝，告警与拒绝分布与未重启逐条一致")
}

// TestSnapshotFileMissingTimePolicyIsRejected 旧格式（缺时间口径）快照
// 必须返回可区分的 ErrTimePolicyMissing，而不是默认顶替。
func TestSnapshotFileMissingTimePolicyIsRejected(t *testing.T) {
	base := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	norm := ingest.NewNormalizer(tpFuture, tpMinAge)
	norm.SetClock(func() time.Time { return base })
	svc := ingest.NewService(norm)
	eng := correlate.NewEngine(restoreCfg(), time.Minute)
	eng.BindIngestService(svc)
	_ = eng.UpsertRule(bruteForceRule(10*time.Second, 1), 1)
	preEvs, _ := tpCollect(t, tpPreRaws(base), svc)
	eng.ProcessBatch(preEvs)

	path := filepath.Join(t.TempDir(), "tp.snap.json")
	if err := eng.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}

	// 通过内存 Encode/Decode 构造一份"校验和自洽但缺时间口径"的快照。
	st := eng.ExportState()
	st.TimePolicy = nil
	data, err := snapshot.Encode(st, "tp-restore-demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Decode(data); !errors.Is(err, snapshot.ErrTimePolicyMissing) {
		t.Fatalf("缺口径快照应 ErrTimePolicyMissing, got %v", err)
	}
	// 负的口径同样明确拒绝，且错误类型可区分。
	neg := eng.ExportState()
	neg.TimePolicy.MaxFutureSkew = -1
	negData, _ := snapshot.Encode(neg, "tp-restore-demo")
	if _, err := snapshot.Decode(negData); !errors.Is(err, snapshot.ErrInvalidTimePolicy) {
		t.Fatalf("负口径应 ErrInvalidTimePolicy, got %v", err)
	}
	// 直接恢复内存状态也应一致拒绝（不落盘路径同样把关）。
	if _, err := correlate.RestoreEngine(st, ingest.NewService(nil)); !errors.Is(err, snapshot.ErrTimePolicyMissing) {
		t.Fatalf("内存恢复缺口径应 ErrTimePolicyMissing, got %v", err)
	}
	t.Log("缺失/非法时间口径与损坏、版本不兼容一样被明确拒绝，绝不默认顶替")
}

// 保证 rule 包在本文件被引用（与其它 e2e 文件一致的配置来源）。
