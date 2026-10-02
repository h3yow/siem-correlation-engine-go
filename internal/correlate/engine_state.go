package correlate

import (
	"sort"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
	"github.com/h3yow/siem-correlation-engine-go/internal/suppress"
)

// ExportState 在引擎锁内把当下全部运行状态拷贝为一份独立的 snapshot.State：
// 水印、迟到容忍度、规则（内容+版本+窗口事件+已告警指纹）、待排空缓冲、
// 抑制桶，以及（若绑定）摄取层幂等去重表。
//
// 快照反映"导出那一刻"的规则版本：运行期 UpsertRule 后的版本与内容
// 原样写入，恢复后规则热更新语义照旧成立。返回值与引擎内部状态完全
// 脱钩，可在锁外安全地做慢磁盘 I/O。
func (e *Engine) ExportState() snapshot.State {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.exportStateLocked()
}

func (e *Engine) exportStateLocked() snapshot.State {
	st := snapshot.State{
		EngineID:        e.id,
		AllowedLateness: snapshot.DurationJSON(e.AllowedLateness),
		Watermark:       e.watermark.UTC(),
		RuleOrder:       append([]string{}, e.ruleOrder...),
		Suppression:     e.suppressor.ExportState(),
		// 以导出那一刻引擎沿用的口径为准（绑定服务时即该服务的实际口径，
		// 未绑定时为摄取层默认口径）。
		TimePolicy: &snapshot.TimePolicyState{
			MaxFutureSkew: snapshot.DurationJSON(e.timePolicy.MaxFutureSkew),
			MinAge:        snapshot.DurationJSON(e.timePolicy.MinAge),
		},
	}
	// 聚合维度属于引擎级抑制配置（抑制器自身不持有），由引擎层补入快照，
	// 恢复后 AggregateKey/桶身份语义保持不变。
	st.Suppression.AggregateBy = append([]string{}, e.suppression.AggregateBy...)
	for _, rid := range e.ruleOrder {
		st.Rules = append(st.Rules, e.rules[rid].ExportState())
	}
	for _, pe := range e.pending {
		st.Pending = append(st.Pending, eventToState(pe.ev))
	}
	if e.ingestSvc != nil {
		st.IngestSeen, st.IngestDupCount = e.ingestSvc.ExportState()
	}
	return st
}

// SaveSnapshot 在锁内拷贝内存状态，然后在锁外完成编码与原子落盘：
// 慢磁盘 I/O 不会卡住正在进行的摄取；反复/周期性导出不会累积临时文件
// 或让内存占用随导出次数增长（每次导出只产生一份一次性的状态拷贝，
// 函数返回后即可被 GC）。
func (e *Engine) SaveSnapshot(path string) error {
	st := e.ExportState()
	engineID := st.EngineID
	return snapshot.SaveToFile(path, st, engineID)
}

// RestoreEngine 从快照状态无损重建引擎：恢复后的引擎继续处理后续事件流，
// 结论与"从未重启"一致——已告警指纹不重复触发，未凑齐的序列靠保留的
// 窗口事件继续参与 DP 重枚举，水印与抑制桶决定迟到/抑制语义不变，
// 事件时间判定口径（未来容忍/最早可回溯）沿用导出那一刻的取值。
//
// svc 可选：传入一个新构造的 ingest.Service 时，会一并恢复幂等去重表，
// 使重启后的重复原始记录投递仍返回 duplicate（快照内无去重表时该服务
// 保持空表），并且快照中的时间口径会强制覆盖该服务构造时的口径——
// 调用方后来传入的设置不会改变恢复结论。任何结构/语义校验失败都返回
// 明确错误（时间口径缺失返回 snapshot.ErrMissingTimePolicy、取值不合理
// 返回 snapshot.ErrInvalidTimePolicy），绝不带病运行或拿默认值顶替。
func RestoreEngine(st snapshot.State, svc *ingest.Service) (*Engine, error) {
	if st.AllowedLateness < 0 {
		return nil, errSnapshotState("allowed_lateness must not be negative")
	}
	// 时间口径是接受/拒绝边界结论的一部分：缺失或不合理必须明确失败，
	// 与文件损坏/版本不兼容一样拒绝恢复，但错误彼此可区分（errors.Is）。
	// Decode 路径已校验过；直接调用 RestoreEngine（内存 State）时这里兜底。
	if err := snapshot.ValidateTimePolicy(st.TimePolicy); err != nil {
		return nil, err
	}
	timePolicy := ingest.TimePolicy{
		MaxFutureSkew: time.Duration(st.TimePolicy.MaxFutureSkew),
		MinAge:        time.Duration(st.TimePolicy.MinAge),
	}

	// 聚合维度以快照为准；兼容早期可能缺失该字段的快照时退回默认维度。
	aggBy := st.Suppression.AggregateBy
	if aggBy == nil {
		aggBy = append([]string{}, rule.DefaultSuppression().AggregateBy...)
	}
	suppCfg := rule.SuppressionConfig{
		AggregateBy:    aggBy,
		QuietFor:       time.Duration(st.Suppression.QuietFor),
		MaxOccurrences: st.Suppression.MaxOccurrences,
	}
	sup, err := suppress.RestoreSuppressor(st.Suppression)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		id:              st.EngineID,
		rules:           map[string]*Detector{},
		suppression:     suppCfg,
		suppressor:      sup,
		AllowedLateness: time.Duration(st.AllowedLateness),
		watermark:       st.Watermark.UTC(),
		timePolicy:      timePolicy,
	}

	// 恢复规则检测器。
	have := map[string]bool{}
	order := append([]string{}, st.RuleOrder...)
	for _, rs := range st.Rules {
		if rs.ID == "" {
			return nil, errSnapshotState("rule entry with empty id")
		}
		if have[rs.ID] {
			return nil, errSnapshotState("rule %s appears more than once", rs.ID)
		}
		have[rs.ID] = true
		d, err := RestoreDetector(rs)
		if err != nil {
			return nil, err
		}
		e.rules[rs.ID] = d
		if !contains(order, rs.ID) {
			order = append(order, rs.ID)
		}
	}
	for _, rid := range order {
		if !have[rid] {
			return nil, errSnapshotState("rule_order references missing rule %q", rid)
		}
	}
	sort.Strings(order)
	e.ruleOrder = order

	// 恢复待排空缓冲（下次 ProcessBatch 时会重新按全序排序，这里原样入列）。
	for _, es := range st.Pending {
		ev := stateToEvent(es)
		if ev.ID == "" || ev.OccurredAt.IsZero() {
			return nil, errSnapshotState("pending event missing id/time")
		}
		e.pending = append(e.pending, pendingEvent{ev: ev})
	}

	// 恢复摄取层幂等去重表（可选）；快照口径强制覆盖该服务自带口径。
	if svc != nil {
		if err := svc.RestoreState(st.IngestSeen, st.IngestDupCount, timePolicy); err != nil {
			return nil, err
		}
		e.ingestSvc = svc
	}
	return e, nil
}

// LoadSnapshotFromFile 从本地快照文件恢复引擎（便捷封装）。
func LoadSnapshotFromFile(path string, svc *ingest.Service) (*Engine, error) {
	st, err := snapshot.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	return RestoreEngine(st, svc)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
