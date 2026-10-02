package correlate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// alertSig 生成跨重启比较用的告警结论签名：包含种类、规则版本、指纹
// （身份）与抑制聚合身份/计数。这些字段必须在恢复前后逐字节一致。
func alertSig(as []alert.Alert) string {
	var s string
	for _, a := range as {
		s += string(a.Kind) + "|" + a.RuleID + "|v" + itoa(a.RuleVersion) +
			"|" + a.DedupKey + "|" + a.AggregateKey + "|occ" + itoa(a.OccurrenceCnt) +
			"|by=" + a.SuppressedBy + ";"
	}
	return s
}

func restoreTestEngine(t *testing.T, lateness time.Duration) (*Engine, time.Duration) {
	t.Helper()
	cfg := rule.SuppressionConfig{
		AggregateBy: []string{"rule_id", "src_ip"}, QuietFor: time.Minute, MaxOccurrences: 10,
	}
	e := NewEngine(cfg, lateness)
	if err := e.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	return e, 10 * time.Second
}

// TestRestoreMidSequenceCompletesAfterRestart 覆盖"恢复点正好落在一个还没
// 凑齐的序列中间"：重启前只到了序列前 3 个事件（2 失败 + 提前到达的锁定，
// 缺第 3 个失败），在该点导出/恢复；恢复后迟到的第 3 个失败到达，
// 必须补齐序列，且结论与从未重启的参照引擎完全一致（不重不漏、指纹相同）。
func TestRestoreMidSequenceCompletesAfterRestart(t *testing.T) {
	evSeq = 0
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	first3 := []event.Event{
		mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root"),
	}
	// 迟到的"中间"事件：事件时间 +2s，在恢复之后才到达。
	lateThird := mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root")
	after := []event.Event{lateThird}

	// 参照：进程从未重启。
	evSeq = 0
	ref, _ := restoreTestEngine(t, 30*time.Second)
	r1 := ref.ProcessBatch(first3)
	r2 := ref.ProcessBatch(after)
	refSig := alertSig(append(append([]alert.Alert{}, r1.Alerts...), r2.Alerts...))
	if n := len(firedAlerts(append(r1.Alerts, r2.Alerts...))); n != 1 {
		t.Fatalf("参照引擎应有 1 条 fired, got %d", n)
	}

	// 重启路径：在序列未凑齐时导出快照并恢复。
	evSeq = 0
	e, _ := restoreTestEngine(t, 30*time.Second)
	before := e.ProcessBatch(first3)
	if len(before.Alerts) != 0 {
		t.Fatalf("序列未凑齐不应有告警, got %d", len(before.Alerts))
	}
	st := e.ExportState()
	if st.Watermark != at(3) {
		t.Fatalf("快照水印应为 %s, got %s", at(3), st.Watermark)
	}
	if len(st.Rules) != 1 || len(st.Rules[0].Fired) != 0 || len(st.Rules[0].Groups) != 1 {
		t.Fatalf("快照规则状态异常: %+v", st.Rules)
	}
	if len(st.Rules[0].Groups[0].Events) != 3 {
		t.Fatalf("窗口应保留 3 个未淘汰事件, got %d", len(st.Rules[0].Groups[0].Events))
	}

	restored, err := RestoreEngine(st, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := restored.ProcessBatch(after)
	if n := len(firedAlerts(got.Alerts)); n != 1 {
		t.Fatalf("恢复后迟到事件补齐序列应恰好 1 fired, got %d", n)
	}
	gotSig := alertSig(append(before.Alerts, got.Alerts...))
	if gotSig != refSig {
		t.Fatalf("恢复前后结论不一致:\nref=%s\ngot=%s", refSig, gotSig)
	}
	wantFP := "e-000001>e-000002>e-000004>e-000003"
	if got.Alerts[0].DedupKey != wantFP {
		t.Fatalf("规范指纹应对得上: want %s got %s", wantFP, got.Alerts[0].DedupKey)
	}
	t.Logf("恢复点在序列中间：恢复后迟到事件补齐，指纹=%s，结论与未重启一致", wantFP)

	// 再重放全部历史事件：已告警指纹随快照恢复，不得重复触发。
	replay := restored.ProcessBatchShuffled(append(first3, after...), 7)
	if n := len(firedAlerts(replay.Alerts)); n != 0 {
		t.Fatalf("恢复后重放历史不得重复告警, got %d", n)
	}
	t.Log("恢复后重放：0 条重复告警")
}

// TestSaveLoadSnapshotFileRestores 通过真实磁盘文件完成一次导出->恢复，
// 并断言版本字段写入文件。
func TestSaveLoadSnapshotFileRestores(t *testing.T) {
	evSeq = 0
	e, _ := newTestEngine(t)
	evs := []event.Event{
		mkEv(base, "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(base.Add(time.Second), "1.1.1.1", "auth.failure", "login_failed", "root"),
	}
	e.ProcessBatch(evs)
	e.SetEngineID("eng-file-1")

	path := filepath.Join(t.TempDir(), "engine.snap.json")
	if err := e.SaveSnapshot(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	restored, err := LoadSnapshotFromFile(path, nil)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if restored.EngineID() != "eng-file-1" {
		t.Fatalf("engine id not restored: %s", restored.EngineID())
	}
	if restored.Watermark() != base.Add(time.Second) {
		t.Fatalf("watermark not restored: %s", restored.Watermark())
	}
	if restored.AllowedLateness != 30*time.Second {
		t.Fatalf("lateness not restored: %s", restored.AllowedLateness)
	}
	if len(restored.ruleOrder) != 1 || restored.ruleOrder[0] != "brute-force" {
		t.Fatalf("rules not restored: %v", restored.ruleOrder)
	}

	// 字节级断言文件带当前版本号。
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "\"format_version\": 1") {
		t.Fatalf("snapshot file missing format_version: %s", string(data))
	}
}

// TestRestoreRejectsInvalidState 快照结构性损坏必须被明确拒绝。
func TestRestoreRejectsInvalidState(t *testing.T) {
	st := snapshot.State{
		AllowedLateness: 0,
		Rules: []snapshot.RuleState{{
			ID: "r1", Version: 1,
			Rule: snapshot.RuleDef{
				ID: "r1", Severity: "high",
				Pattern: []snapshot.MatchDef{{EventType: "auth.failure"}},
				Window:  0, // 非法：window 必须为正
			},
		}},
	}
	if _, err := RestoreEngine(st, nil); err == nil {
		t.Fatal("非法规则快照必须被拒绝")
	}

	// rule_order 引用了不存在的规则也必须拒绝。
	st2 := st
	st2.Rules[0].Rule.Window = snapshot.DurationJSON(10 * time.Second)
	st2.RuleOrder = []string{"missing"}
	if _, err := RestoreEngine(st2, nil); err == nil {
		t.Fatal("悬空 rule_order 引用必须被拒绝")
	}
}

// TestLateAndOutOfOrderEventsCrossRestoreBoundary 覆盖迟到、乱序事件
// 跨过恢复边界：
//
//	时间线（src=1.1.1.1 的 4 步序列 0,1,2,3s）：
//	  重启前到达: t3(锁定,3s)、t0(失败,0s)        —— 乱序，缺中间事件
//	  ------ 导出快照 / 新进程恢复 ------
//	  重启后到达: t2(失败,2s，迟到的中间事件)、t1(失败,1s，更晚到达)
//	恢复后的引擎仍必须补全唯一序列并恰好告警一次；重复投递的 t0 不得
//	产生任何副作用。最终结论与"同一进程顺序处理"完全一致。
func TestLateAndOutOfOrderEventsCrossRestoreBoundary(t *testing.T) {
	evSeq = 0
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	f0 := mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root")
	f1 := mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root")
	f2 := mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root")
	l3 := mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root")
	all := []event.Event{f0, f1, f2, l3}

	// 参照：单一进程，同样的乱序/迟到到达序列（最后还重复投递一次 f0）。
	evSeq = 0
	ref, _ := restoreTestEngine(t, 30*time.Second)
	rr1 := ref.ProcessBatch([]event.Event{l3, f0})
	rr2 := ref.ProcessBatch([]event.Event{f2, f1})
	rr3 := ref.ProcessBatch([]event.Event{f0}) // 重启后重复投递
	refAll := append(append(rr1.Alerts, rr2.Alerts...), rr3.Alerts...)
	refRej := append(append(rr1.Rejected, rr2.Rejected...), rr3.Rejected...)
	if n := len(firedAlerts(refAll)); n != 1 {
		t.Fatalf("参照应有 1 fired, got %d", n)
	}

	// 重启路径。
	evSeq = 0
	e, _ := restoreTestEngine(t, 30*time.Second)
	before := e.ProcessBatch([]event.Event{l3, f0})
	if len(before.Alerts) != 0 {
		t.Fatalf("重启前序列不完整不应告警, got %d", len(before.Alerts))
	}
	st := e.ExportState()
	restored, err := RestoreEngine(st, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	after := restored.ProcessBatch([]event.Event{f2, f1})
	dup := restored.ProcessBatch([]event.Event{f0})

	gotAll := append(append([]alert.Alert{}, before.Alerts...), after.Alerts...)
	gotAll = append(gotAll, dup.Alerts...)
	if n := len(firedAlerts(gotAll)); n != 1 {
		t.Fatalf("跨恢复边界应恰好 1 fired, got %d", n)
	}
	if alertSig(gotAll) != alertSig(refAll) {
		t.Fatalf("跨边界结论与未重启不一致:\nref=%s\ngot=%s", alertSig(refAll), alertSig(gotAll))
	}
	// 恢复后的指纹必须是全序规范序列，和参照逐字节相同。
	if firedAlerts(gotAll)[0].DedupKey != firedAlerts(refAll)[0].DedupKey {
		t.Fatalf("指纹对不上: got %s want %s",
			firedAlerts(gotAll)[0].DedupKey, firedAlerts(refAll)[0].DedupKey)
	}
	// 参照路径同样没有拒绝：边界内的迟到事件参与检测；重复投递在引擎层
	// 只是再次进入窗口，由永久指纹集合兜底（告警层 0 新增）。
	if len(refRej) != 0 || len(dup.Rejected) != 0 {
		t.Fatalf("边界内重复/迟到不应产生拒绝, ref=%+v got=%+v", refRej, dup.Rejected)
	}

	// 恢复后再以任意乱序全量重放整段序列：跨重启恢复的永久指纹集合
	// 必须保证 0 条重复告警。
	replay := restored.ProcessBatchShuffled(all, 12345)
	if n := len(firedAlerts(replay.Alerts)); n != 0 {
		t.Fatalf("恢复后全量乱序重放不得重复告警, got %d", n)
	}
	t.Log("迟到+乱序跨过恢复边界：唯一序列在恢复后补齐，身份一致；重放 0 重复")
	t.Log("\n" + restored.DumpState())
}

// TestWatermarkAndLatenessCrossRestore 恢复后水印继续生效：超过
// watermark-AllowedLateness 的事件仍以 too_late 拒绝，且阈值与未重启相同。
func TestWatermarkAndLatenessCrossRestore(t *testing.T) {
	evSeq = 0
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	eng, _ := restoreTestEngine(t, 30*time.Second)
	eng.ProcessBatch([]event.Event{
		mkEv(at(0), "9.9.9.9", "auth.failure", "x", "u"),
		mkEv(at(60), "9.9.9.9", "auth.failure", "x", "u"), // 推进水印到 60s
	})
	st := eng.ExportState()
	restored, err := RestoreEngine(st, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	res := restored.ProcessBatch([]event.Event{
		mkEv(at(10), "9.9.9.9", "auth.failure", "x", "u"), // 早于 60-30=30s => too_late
	})
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != event.Reason("too_late") {
		t.Fatalf("恢复后迟到判定应保持, got %+v", res.Rejected)
	}
	t.Logf("恢复后水印/迟到容忍语义不变: %s", res.Rejected[0].Detail)
}

// fullSeq 构造一次完整的"3 失败 + 1 锁定"序列，事件时间从 startSec 起。
func fullSeq(startSec int, ip string) []event.Event {
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	return []event.Event{
		mkEv(at(startSec+0), ip, "auth.failure", "login_failed", "root"),
		mkEv(at(startSec+1), ip, "auth.failure", "login_failed", "root"),
		mkEv(at(startSec+2), ip, "auth.failure", "login_failed", "root"),
		mkEv(at(startSec+3), ip, "auth.locked", "locked", "root"),
	}
}

// TestSuppressionStateSurvivesRestore 重启前已开的抑制桶必须随快照恢复：
// 重启后在同一静默期内的再次命中仍是 suppressed，且 OccurrenceCnt 接着
// 累加、SuppressedBy 指向同一条首告警指纹——与未重启完全一致。
func TestSuppressionStateSurvivesRestore(t *testing.T) {
	evSeq = 0
	mkEng := func() *Engine {
		cfg := rule.SuppressionConfig{
			AggregateBy: []string{"rule_id", "src_ip"},
			QuietFor:    10 * time.Minute, MaxOccurrences: 50,
		}
		e := NewEngine(cfg, time.Minute)
		// 宽松窗口 + MaxGap，确保两组事件各自只规范命中本周期序列。
		r := bruteForceRule(time.Hour)
		r.MaxGap = 5 * time.Second
		_ = e.UpsertRule(r, 1)
		return e
	}

	// 参照：未重启，连续两个周期。
	evSeq = 0
	ref := mkEng()
	ref.ProcessBatch(fullSeq(0, "5.5.5.5"))
	refRes := ref.ProcessBatch(fullSeq(10, "5.5.5.5"))

	// 重启路径：第一个周期后导出，恢复后再跑第二个周期。
	evSeq = 0
	e := mkEng()
	e.ProcessBatch(fullSeq(0, "5.5.5.5"))
	st := e.ExportState()
	if len(st.Suppression.Buckets) != 1 || st.Suppression.Buckets[0].OccurrenceCnt != 1 {
		t.Fatalf("抑制桶未正确导出: %+v", st.Suppression)
	}
	restored, err := RestoreEngine(st, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	gotRes := restored.ProcessBatch(fullSeq(10, "5.5.5.5"))

	var refSupp, gotSupp []alert.Alert
	for _, a := range refRes.Alerts {
		if a.Kind == alert.KindSuppressed {
			refSupp = append(refSupp, a)
		}
	}
	for _, a := range gotRes.Alerts {
		if a.Kind == alert.KindSuppressed {
			gotSupp = append(gotSupp, a)
		}
	}
	if len(gotSupp) != 1 || len(refSupp) != 1 {
		t.Fatalf("静默期内应各有 1 条 suppressed: ref=%d got=%d", len(refSupp), len(gotSupp))
	}
	if gotSupp[0].OccurrenceCnt != 2 || gotSupp[0].OccurrenceCnt != refSupp[0].OccurrenceCnt {
		t.Fatalf("抑制计数未跨重启接续: got=%d ref=%d", gotSupp[0].OccurrenceCnt, refSupp[0].OccurrenceCnt)
	}
	if gotSupp[0].SuppressedBy != refSupp[0].SuppressedBy ||
		gotSupp[0].AggregateKey != refSupp[0].AggregateKey {
		t.Fatalf("抑制身份跨重启不一致: got by=%s key=%s; ref by=%s key=%s",
			gotSupp[0].SuppressedBy, gotSupp[0].AggregateKey,
			refSupp[0].SuppressedBy, refSupp[0].AggregateKey)
	}
	if alertSig(gotRes.Alerts) != alertSig(refRes.Alerts) {
		t.Fatalf("抑制结论跨重启不一致:\nref=%s\ngot=%s",
			alertSig(refRes.Alerts), alertSig(gotRes.Alerts))
	}
	t.Logf("抑制桶跨重启接续: occ=%d by=%s key=%s",
		gotSupp[0].OccurrenceCnt, gotSupp[0].SuppressedBy, gotSupp[0].AggregateKey)
}

// TestRuleHotUpdateVersionInSnapshot 运行期改过规则后，快照必须反映当时的
// 规则版本与内容；恢复后该版本继续生效，且历史告警不重复。
func TestRuleHotUpdateVersionInSnapshot(t *testing.T) {
	evSeq = 0
	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute}
	e := NewEngine(cfg, 60*time.Second)
	_ = e.UpsertRule(bruteForceRule(10*time.Second), 1)
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	e.ProcessBatch([]event.Event{
		mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root"),
	})
	updated := bruteForceRule(30 * time.Second)
	updated.Name = "SSH brute force (widened)"
	if err := e.UpsertRule(updated, 2); err != nil {
		t.Fatalf("update: %v", err)
	}

	st := e.ExportState()
	if len(st.Rules) != 1 || st.Rules[0].Version != 2 ||
		time.Duration(st.Rules[0].Rule.Window) != 30*time.Second {
		t.Fatalf("快照未反映热更新后的规则: %+v", st.Rules[0])
	}
	restored, err := RestoreEngine(st, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if d := restored.Detectors()["brute-force"]; d == nil || d.RuleVersion() != 2 {
		t.Fatalf("恢复后规则版本应为 2")
	}
	// 恢复后补齐锁定事件：保留的窗口状态 + v2 规则产生 v2 告警。
	lock := mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root")
	res := restored.ProcessBatch([]event.Event{lock})
	fired := firedAlerts(res.Alerts)
	if len(fired) != 1 || fired[0].RuleVersion != 2 {
		t.Fatalf("恢复后应产生 1 条 v2 告警, got %+v", res.Alerts)
	}
	// 再热更新到 v3 后语义照旧：状态仍保留、历史不重复。
	v3 := bruteForceRule(45 * time.Second)
	if err := restored.UpsertRule(v3, 3); err != nil {
		t.Fatalf("upsert v3: %v", err)
	}
	if n := len(firedAlerts(restored.ProcessBatch(fullSeq(0, "1.1.1.1")).Alerts)); n != 0 {
		t.Fatalf("恢复后规则热更新语义应照旧（历史不重复）, got %d", n)
	}
	t.Log("热更新版本/内容随快照保存，恢复后规则变更语义照旧，历史不重复")
}

// TestConcurrentExportsDoNotBlockOrGrow 导出与并发摄取同时进行：
// race 检测器下必须安全；反复导出不应让引擎内存随导出次数增长
// （通过多次导出后状态仍正确、且临时文件不泄漏间接保证无资源累积）。
func TestConcurrentExportsDoNotBlockOrGrow(t *testing.T) {
	evSeq = 0
	e, _ := restoreTestEngine(t, 30*time.Second)
	dir := t.TempDir()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// 并发摄取：多 goroutine 各自小批量投递事件。不使用共享的 mkEv
	// （它带包级序号），这里以 (g,i) 构造确定性、互不相同的事件。
	mkLocal := func(g, i int) event.Event {
		return event.Event{
			ID:         "race-" + itoa(g) + "-" + itoa(i),
			OccurredAt: base.Add(time.Duration(g*100+i) * time.Second),
			Source:     "sshd", EventType: "auth.failure",
			SrcIP: "7.7.7.7", User: "u", Action: "x", SrcHost: "h",
		}
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				select {
				case <-stop:
					return
				default:
				}
				e.ProcessEvent(mkLocal(g, i))
			}
		}(g)
	}
	// 并发、周期性导出到不同文件。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			select {
			case <-stop:
				return
			default:
			}
			_ = e.SaveSnapshot(filepath.Join(dir, "cur.snap.json"))
		}
	}()
	wg.Wait()
	close(stop)

	// 最终再导出一次并恢复：恢复必须成功且不报错。
	final := filepath.Join(dir, "final.snap.json")
	if err := e.SaveSnapshot(final); err != nil {
		t.Fatalf("final save: %v", err)
	}
	restored, err := LoadSnapshotFromFile(final, nil)
	if err != nil {
		t.Fatalf("restore after concurrent export: %v", err)
	}
	if restored.Watermark() != e.Watermark() {
		t.Fatalf("最终水印不一致: %s vs %s", restored.Watermark(), e.Watermark())
	}
	fis, _ := os.ReadDir(dir)
	for _, fi := range fis {
		if strings.HasPrefix(fi.Name(), ".snapshot-") {
			t.Fatalf("并发导出泄漏临时文件: %s", fi.Name())
		}
	}
}

// TestPendingBufferSurvivesRestore 只缓冲未排空（BufferEvent）的事件也必须
// 随快照保存：它们尚未参与检测，恢复后下一次排空按全序进入检测器，
// 与这些事件在重启后才到达完全一致（不漏）。
func TestPendingBufferSurvivesRestore(t *testing.T) {
	evSeq = 0
	at := func(s int) time.Time { return base.Add(time.Duration(s) * time.Second) }
	// 用乱序顺序缓冲（末事件先到）3 个事件，快照时 pending=3 且无任何检测发生。
	evs := []event.Event{
		mkEv(at(3), "1.1.1.1", "auth.locked", "locked", "root"),
		mkEv(at(0), "1.1.1.1", "auth.failure", "login_failed", "root"),
		mkEv(at(1), "1.1.1.1", "auth.failure", "login_failed", "root"),
	}
	e, _ := restoreTestEngine(t, 30*time.Second)
	for _, ev := range evs {
		e.BufferEvent(ev)
	}
	st := e.ExportState()
	if len(st.Pending) != 3 {
		t.Fatalf("pending 应入快照, got %d", len(st.Pending))
	}
	restored, err := RestoreEngine(st, nil)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// 参照：同样 3 个事件在一个全新引擎里只缓冲、不排空。
	// 复位全局测试序号并推进到与恢复路径相同的位置，使"缺失的第 3 个
	// 失败"在两条路径上拿到相同事件 ID，比较的是逻辑结论而非测试计数器。
	evSeq = 0
	ref, _ := restoreTestEngine(t, 30*time.Second)
	for _, ev := range evs {
		ref.BufferEvent(ev)
	}
	// 恢复路径此前 3 次 mkEv 已把序号推到 3；参照复位后补齐这 3 次推进。
	for i := 0; i < len(evs); i++ {
		evSeq++
	}
	missing := mkEv(at(2), "1.1.1.1", "auth.failure", "login_failed", "root")
	restored.BufferEvent(missing)
	ref.BufferEvent(missing.Clone())
	gotRes := restored.ProcessBatch(nil)
	refRes := ref.ProcessBatch(nil)
	if n := len(firedAlerts(gotRes.Alerts)); n != 1 {
		t.Fatalf("恢复后排空应发现唯一序列, got fired=%d", n)
	}
	if alertSig(gotRes.Alerts) != alertSig(refRes.Alerts) {
		t.Fatalf("pending 跨重启后结论不一致:\nref=%s\ngot=%s",
			alertSig(refRes.Alerts), alertSig(gotRes.Alerts))
	}
	t.Log("未排空缓冲随快照保存，恢复后乱序缓冲→全序排空，序列不漏")
}

// TestTimePolicySurvivesEngineRestore 非默认时间口径必须随引擎快照导出，
// 恢复后引擎与绑定的摄取服务都沿用快照口径，不被恢复方构造服务时传入的
// 默认设置覆盖。
func TestTimePolicySurvivesEngineRestore(t *testing.T) {
	evSeq = 0
	policy := ingest.TimePolicy{MaxFutureSkew: 45 * time.Second, MinAge: 3 * time.Minute}
	norm := ingest.NewNormalizer(policy.MaxFutureSkew, policy.MinAge)
	svc := ingest.NewService(norm)

	cfg := rule.SuppressionConfig{AggregateBy: []string{"rule_id"}, QuietFor: time.Minute}
	eng := NewEngine(cfg, 30*time.Second)
	eng.BindIngestService(svc)
	if eng.TimePolicy() != policy {
		t.Fatalf("绑定后引擎口径应取自摄取服务: got %+v", eng.TimePolicy())
	}
	_ = eng.UpsertRule(bruteForceRule(10*time.Second), 1)
	eng.ProcessBatch([]event.Event{
		mkEv(base, "1.1.1.1", "auth.failure", "x", "u"),
	})

	st := eng.ExportState()
	if st.TimePolicy == nil {
		t.Fatal("导出状态必须带 time_policy")
	}
	if time.Duration(st.TimePolicy.MaxFutureSkew) != policy.MaxFutureSkew ||
		time.Duration(st.TimePolicy.MinAge) != policy.MinAge {
		t.Fatalf("快照口径不正确: %+v", st.TimePolicy)
	}

	// 恢复方用默认口径新服务，恢复后必须被快照覆盖。
	newSvc := ingest.NewService(nil)
	restored, err := RestoreEngine(st, newSvc)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.TimePolicy() != policy {
		t.Fatalf("恢复后引擎口径: got %+v want %+v", restored.TimePolicy(), policy)
	}
	if newSvc.ExportTimePolicy() != policy {
		t.Fatalf("恢复后摄取服务口径必须被快照覆盖: got %+v", newSvc.ExportTimePolicy())
	}
	t.Logf("时间口径随快照恢复: skew=%s minAge=%s",
		restored.TimePolicy().MaxFutureSkew, restored.TimePolicy().MinAge)
}

// TestRestoreMissingTimePolicyErrors 内存 State 缺时间口径必须报错。
func TestRestoreMissingTimePolicyErrors(t *testing.T) {
	st := snapshot.State{
		AllowedLateness: 0,
		Rules: []snapshot.RuleState{{
			ID: "r1", Version: 1,
			Rule: snapshot.RuleDef{ID: "r1", Severity: "high", Window: snapshot.DurationJSON(10 * time.Second)},
		}},
		RuleOrder: []string{"r1"},
	}
	_, err := RestoreEngine(st, nil)
	if !errors.Is(err, snapshot.ErrMissingTimePolicy) {
		t.Fatalf("缺时间口径应报 ErrMissingTimePolicy, got %v", err)
	}
}
