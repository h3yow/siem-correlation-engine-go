package e2e_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// 本文件专门回归上一轮快照恢复的遗留问题：事件时间判定口径
// （对未来事件的容忍 MaxFutureSkew、最早可回溯 MinAge）没有随快照延续，
// 新进程悄悄退回默认口径，导致边界附近记录的接受/拒绝与告警分布对不上。

// tightPolicy 是一套刻意收紧、明显区别于默认（1h future / 不限年龄）的口径。
func tightPolicy() ingest.TimePolicy {
	return ingest.TimePolicy{MaxFutureSkew: 30 * time.Second, MinAge: 2 * time.Minute}
}

// boundaryClock 是导出/恢复两侧共用的固定墙钟，保证边界判定可复现。
var boundaryClock = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

// rawRecord 构造一条带唯一标签的 JSON 记录（内容唯一 => 幂等键唯一）。
func rawRecord(at time.Time, tag, srcIP, evType, action string) string {
	rec := map[string]any{
		"timestamp":  at.UTC().Format(time.RFC3339),
		"source":     "sshd",
		"event_type": evType,
		"src_ip":     srcIP,
		"user":       "root",
		"action":     action,
		"tag":        tag,
	}
	b, _ := json.Marshal(rec)
	return string(b)
}

func rawAuthRecord(at time.Time, tag, srcIP string) string {
	return rawRecord(at, tag, srcIP, "auth.failure", "login_failed")
}

// boundaryCase 描述一条在恢复后到达的、位于时间口径边界附近的记录。
type boundaryCase struct {
	name   string
	at     time.Time
	accept bool // 期望在该非默认口径下被接受（true）还是 future/too_old 拒绝（false）
	reason event.Reason
}

// boundaryCases 覆盖"刚好处在容忍范围内、刚好超出、最早可回溯边界两侧"。
// 判定规则（clock=09:00:00, skew=30s, minAge=2m）：
//   - ts >  09:00:30        => future_event 拒绝
//   - ts == 09:00:30        => 临界等于上界，接受（After 为假）
//   - 08:58:00 <= ts <= ... => 接受
//   - ts == 08:58:00        => 临界等于最早边界，接受（Before 为假）
//   - ts <  08:58:00        => too_old 拒绝
func boundaryCases() []boundaryCase {
	c := boundaryClock
	return []boundaryCase{
		{"future-far-beyond", c.Add(10 * time.Minute), false, event.ReasonFutureEvent},
		{"future-1s-over", c.Add(31 * time.Second), false, event.ReasonFutureEvent},
		{"future-at-edge", c.Add(30 * time.Second), true, ""},
		{"future-1s-inside", c.Add(29 * time.Second), true, ""},
		{"now", c, true, ""},
		{"old-1s-inside", c.Add(-119 * time.Second), true, ""},
		{"old-at-edge", c.Add(-120 * time.Second), true, ""},
		{"old-1s-over", c.Add(-121 * time.Second), false, event.ReasonTooOld},
		{"old-far-beyond", c.Add(-30 * time.Minute), false, event.ReasonTooOld},
	}
}

// ingestOutcome 签名化单条记录的摄取结论。
func ingestOutcome(ir ingest.IngestResult) string {
	if ir.Accepted() {
		return "accept:" + ir.Event.ID
	}
	return "reject:" + string(ir.Rejected.Reason)
}

// resultByRaw 按原始记录建索引（IngestConcurrent 会重排结果顺序）。
func resultByRaw(irs []ingest.IngestResult) map[string]ingest.IngestResult {
	m := make(map[string]ingest.IngestResult, len(irs))
	for _, ir := range irs {
		if ir.Accepted() {
			m[ir.Event.Raw] = ir
		} else {
			m[ir.Rejected.Raw] = ir
		}
	}
	return m
}

// newPolicyEngine 构造使用指定时间口径、固定时钟并绑定摄取服务的引擎。
func newPolicyEngine(t *testing.T, policy ingest.TimePolicy) (*correlate.Engine, *ingest.Service) {
	t.Helper()
	norm := ingest.NewNormalizer(policy.MaxFutureSkew, policy.MinAge)
	norm.SetClock(func() time.Time { return boundaryClock })
	svc := ingest.NewService(norm)
	cfg := rule.SuppressionConfig{
		AggregateBy: []string{"rule_id", "src_ip"}, QuietFor: time.Minute, MaxOccurrences: 100,
	}
	eng := correlate.NewEngine(cfg, time.Minute)
	eng.BindIngestService(svc)
	if err := eng.UpsertRule(bruteForceRule(time.Minute, 1), 1); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return eng, svc
}

func ingestAllMustAccept(t *testing.T, svc *ingest.Service, raws []string) []event.Event {
	t.Helper()
	irs := svc.IngestConcurrent(raws)
	var evs []event.Event
	for _, ir := range irs {
		if !ir.Accepted() {
			t.Fatalf("前置记录应全部接受, got reject %s: %s", ir.Rejected.Reason, ir.Rejected.Detail)
		}
		evs = append(evs, ir.Event)
	}
	return evs
}

func externalFired(as []alert.Alert) []alert.Alert {
	var out []alert.Alert
	for _, a := range as {
		if a.Kind == alert.KindFired {
			out = append(out, a)
		}
	}
	return out
}

func externalAlertSig(as []alert.Alert) string {
	s := ""
	for _, a := range as {
		s += fmt.Sprintf("%s|%s|v%d|%s|%s|occ%d|by=%s;",
			a.Kind, a.RuleID, a.RuleVersion, a.DedupKey,
			a.AggregateKey, a.OccurrenceCnt, a.SuppressedBy)
	}
	return s
}

// TestNonDefaultTimePolicySurvivesRestore 核心回归：非默认时间口径下运行
// 中途导出快照，在新进程恢复，再继续喂边界附近事件；断言恢复前后逐条
// 接受/拒绝结论一致、告警结论一致，且每条记录的期望本身正确（不误放、
// 不误拒）。
func TestNonDefaultTimePolicySurvivesRestore(t *testing.T) {
	policy := tightPolicy()
	cases := boundaryCases()

	// 重启前先喂 5 失败 + 1 锁定（窗口 1m 内），制造水位/规则状态，恰好
	// 命中一次 Fired，使导出时引擎确有运行中状态。
	preRaws := []string{
		rawAuthRecord(boundaryClock.Add(-5*time.Second), "pre-f1", "10.0.0.1"),
		rawAuthRecord(boundaryClock.Add(-4*time.Second), "pre-f2", "10.0.0.1"),
		rawAuthRecord(boundaryClock.Add(-3*time.Second), "pre-f3", "10.0.0.1"),
		rawAuthRecord(boundaryClock.Add(-2*time.Second), "pre-f4", "10.0.0.1"),
		rawAuthRecord(boundaryClock.Add(-1*time.Second), "pre-f5", "10.0.0.1"),
		rawRecord(boundaryClock, "pre-lock", "10.0.0.1", "auth.locked", "locked"),
	}
	afterRaws := make([]string, len(cases))
	for i, tc := range cases {
		afterRaws[i] = rawAuthRecord(tc.at, "post-"+tc.name, "10.0.0.2")
	}

	// ---------- 参照路径：单进程，从未重启 ----------
	refEng, refSvc := newPolicyEngine(t, policy)
	refPreRes := refEng.ProcessBatch(ingestAllMustAccept(t, refSvc, preRaws))
	refAfterIR := refSvc.IngestConcurrent(afterRaws)
	var refAfterEvs []event.Event
	for _, ir := range refAfterIR {
		if ir.Accepted() {
			refAfterEvs = append(refAfterEvs, ir.Event)
		}
	}
	refAfterRes := refEng.ProcessBatch(refAfterEvs)

	// ---------- 重启路径：处理完前缀后导出，新进程恢复 ----------
	dumpEng, dumpSvc := newPolicyEngine(t, policy)
	dumpPreRes := dumpEng.ProcessBatch(ingestAllMustAccept(t, dumpSvc, preRaws))

	st := dumpEng.ExportState()
	if st.TimePolicy == nil {
		t.Fatal("快照必须携带 time_policy 节")
	}
	if got := time.Duration(st.TimePolicy.MaxFutureSkew); got != policy.MaxFutureSkew {
		t.Fatalf("快照 future skew 应为 %s, got %s", policy.MaxFutureSkew, got)
	}
	if got := time.Duration(st.TimePolicy.MinAge); got != policy.MinAge {
		t.Fatalf("快照 min age 应为 %s, got %s", policy.MinAge, got)
	}
	path := filepath.Join(t.TempDir(), "policy.snap.json")
	if err := dumpEng.SaveSnapshot(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// 新进程刻意用"另一套口径"（默认口径）构造服务：恢复必须以快照为准，
	// 不被这里传入的设置覆盖。时钟是进程本地墙钟（不属快照），测试里
	// 注入同一面固定钟以确定性地比较边界；口径仍故意保留默认。
	restoredNorm := ingest.NewNormalizer(ingest.DefaultMaxFutureSkew, ingest.DefaultMinAge)
	restoredNorm.SetClock(func() time.Time { return boundaryClock })
	restoredSvc := ingest.NewService(restoredNorm)
	if got := restoredSvc.ExportTimePolicy(); got.MaxFutureSkew != ingest.DefaultMaxFutureSkew {
		t.Fatalf("恢复前服务应是默认口径, got %+v", got)
	}
	restoredEng, err := correlate.LoadSnapshotFromFile(path, restoredSvc)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if rp := restoredEng.TimePolicy(); rp != policy {
		t.Fatalf("恢复后引擎口径必须等于快照口径: got %+v want %+v", rp, policy)
	}
	if rp := restoredSvc.ExportTimePolicy(); rp != policy {
		t.Fatalf("恢复后摄取服务口径必须被快照覆盖，不应保留默认: got %+v want %+v", rp, policy)
	}

	gotAfterIR := restoredSvc.IngestConcurrent(afterRaws)
	var gotAfterEvs []event.Event
	for _, ir := range gotAfterIR {
		if ir.Accepted() {
			gotAfterEvs = append(gotAfterEvs, ir.Event)
		}
	}
	gotAfterRes := restoredEng.ProcessBatch(gotAfterEvs)

	// ---------- 断言 1：每条边界记录的期望本身成立（参照路径） ----------
	refByRaw, gotByRaw := resultByRaw(refAfterIR), resultByRaw(gotAfterIR)
	for _, tc := range cases {
		raw := rawAuthRecord(tc.at, "post-"+tc.name, "10.0.0.2")
		ir := refByRaw[raw]
		if ir.Accepted() != tc.accept {
			t.Fatalf("[%s] 参照口径期望 accept=%v 但得到 %v (%+v)",
				tc.name, tc.accept, ir.Accepted(), ir.Rejected)
		}
		if !tc.accept && ir.Rejected.Reason != tc.reason {
			t.Fatalf("[%s] 拒绝原因期望 %s got %s", tc.name, tc.reason, ir.Rejected.Reason)
		}
		t.Logf("边界用例 %-18s at=%s => %s",
			tc.name, tc.at.Format("15:04:05"), ingestOutcome(ir))
	}

	// ---------- 断言 2：恢复前后逐条结论一致 ----------
	var mismatch []string
	for _, tc := range cases {
		raw := rawAuthRecord(tc.at, "post-"+tc.name, "10.0.0.2")
		want, got := ingestOutcome(refByRaw[raw]), ingestOutcome(gotByRaw[raw])
		if want != got {
			mismatch = append(mismatch, fmt.Sprintf("%s: 未重启=%s 恢复后=%s", tc.name, want, got))
		}
	}
	if len(mismatch) > 0 {
		t.Fatalf("恢复后边界结论与未重启不一致:\n%v", mismatch)
	}

	// ---------- 断言 3：接受/拒绝分布一致 ----------
	dist := func(irs []ingest.IngestResult) map[string]int {
		m := map[string]int{}
		for _, ir := range irs {
			if ir.Accepted() {
				m["accepted"]++
			} else {
				m[string(ir.Rejected.Reason)]++
			}
		}
		return m
	}
	rd, gd := dist(refAfterIR), dist(gotAfterIR)
	t.Logf("边界事件分布: 未重启=%v 恢复后=%v", rd, gd)
	if fmt.Sprint(rd) != fmt.Sprint(gd) {
		t.Fatalf("接受/拒绝分布不一致: ref=%v got=%v", rd, gd)
	}
	if rd["accepted"] != 5 || rd["future_event"] != 2 || rd["too_old"] != 2 {
		t.Fatalf("边界用例计数不符合设计: %v", rd)
	}

	// ---------- 断言 4：告警结论一致（前缀序列 Fired=1，恢复后不误判） ----------
	refAlerts := append(append([]alert.Alert{}, refPreRes.Alerts...), refAfterRes.Alerts...)
	gotAlerts := append(append([]alert.Alert{}, dumpPreRes.Alerts...), gotAfterRes.Alerts...)
	if len(externalFired(refAlerts)) != 1 {
		t.Fatalf("参照路径应恰好 1 条 Fired, got %d", len(externalFired(refAlerts)))
	}
	if len(externalFired(gotAlerts)) != 1 {
		t.Fatalf("恢复路径应恰好 1 条 Fired, got %d", len(externalFired(gotAlerts)))
	}
	if externalAlertSig(refAlerts) != externalAlertSig(gotAlerts) {
		t.Fatalf("告警结论跨恢复不一致:\nref=%s\ngot=%s",
			externalAlertSig(refAlerts), externalAlertSig(gotAlerts))
	}
	t.Logf("非默认口径(skew=%s,minAge=%s)跨进程恢复：9 条边界事件逐条一致，Fired=1",
		policy.MaxFutureSkew, policy.MinAge)
}

// reencodeSnapshot 读出快照信封，在解码校验前修改内容（绕过 Decode 的
// 严格校验），返回修改后的原始字节；rechecksum 控制是否重算校验和。
func reencodeSnapshot(t *testing.T, path string, mut func(env *snapshot.Envelope), rechecksum bool) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env snapshot.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	mut(&env)
	if rechecksum {
		b, err := snapshot.Canonical(env.State)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		env.Checksum = hex.EncodeToString(sum[:])
	}
	out, err := json.Marshal(&env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRestoreRejectsMissingOrInvalidTimePolicy 时间口径缺失/取值不合理
// 必须明确报错，且能与"文件损坏""版本不兼容"区分；不能拿默认值顶替。
func TestRestoreRejectsMissingOrInvalidTimePolicy(t *testing.T) {
	policy := tightPolicy()
	eng, svc := newPolicyEngine(t, policy)
	eng.ProcessBatch(ingestAllMustAccept(t, svc, []string{
		rawAuthRecord(boundaryClock.Add(-1*time.Second), "warmup", "10.0.0.9"),
	}))
	path := filepath.Join(t.TempDir(), "p.snap.json")
	if err := eng.SaveSnapshot(path); err != nil {
		t.Fatal(err)
	}

	// 1) 去掉 time_policy 节并重算校验和（保证不是 checksum 错误）：
	//    必须报 ErrMissingTimePolicy。
	stripped := reencodeSnapshot(t, path, func(env *snapshot.Envelope) {
		env.State.TimePolicy = nil
	}, true)
	if _, err := snapshot.Decode(stripped); !errors.Is(err, snapshot.ErrMissingTimePolicy) {
		t.Fatalf("缺失口径应报 ErrMissingTimePolicy, got %v", err)
	} else {
		t.Logf("缺失口径被明确拒绝: %v", err)
	}
	// 直接用内存 State 恢复：nil 口径同样被拦在引擎层（Decode 之外的兜底）。
	mem := eng.ExportState()
	mem.TimePolicy = nil
	if _, err := correlate.RestoreEngine(mem, nil); !errors.Is(err, snapshot.ErrMissingTimePolicy) {
		t.Fatalf("内存恢复 nil 口径应报 ErrMissingTimePolicy, got %v", err)
	}

	// 2) 非法取值（负时长）=> ErrInvalidTimePolicy。
	bad := eng.ExportState()
	bad.TimePolicy.MaxFutureSkew = -1
	if _, err := correlate.RestoreEngine(bad, nil); !errors.Is(err, snapshot.ErrInvalidTimePolicy) {
		t.Fatalf("负 skew 应报 ErrInvalidTimePolicy, got %v", err)
	}
	bad2 := eng.ExportState()
	bad2.TimePolicy.MinAge = -1
	if _, err := correlate.RestoreEngine(bad2, nil); !errors.Is(err, snapshot.ErrInvalidTimePolicy) {
		t.Fatalf("负 minAge 应报 ErrInvalidTimePolicy, got %v", err)
	}
	t.Log("时间口径缺失 / 取值非法 均被明确拒绝")

	// 3) 三类失败互不混淆：版本不兼容 / 校验和损坏 / 口径缺失。
	versionBad := reencodeSnapshot(t, path, func(env *snapshot.Envelope) {
		env.FormatVersion = snapshot.CurrentFormatVersion + 1
	}, false)
	if _, err := snapshot.Decode(versionBad); !errors.Is(err, snapshot.ErrUnsupportedVersion) {
		t.Fatalf("版本错误分类不对: %v", err)
	}
	checksumBad := reencodeSnapshot(t, path, func(env *snapshot.Envelope) {
		env.State.EngineID = "tampered" // 改状态但不重算 checksum
	}, false)
	if _, err := snapshot.Decode(checksumBad); !errors.Is(err, snapshot.ErrChecksumMismatch) {
		t.Fatalf("校验和错误分类不对: %v", err)
	}
	// 原始快照本身仍可正常恢复（对照）。
	if _, err := correlate.LoadSnapshotFromFile(path, ingest.NewService(nil)); err != nil {
		t.Fatalf("原始快照应能正常恢复, got %v", err)
	}
	t.Log("版本不兼容 / 校验和损坏 / 时间口径缺失 三类失败彼此可区分")
}
