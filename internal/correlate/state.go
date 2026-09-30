package correlate

import (
	"sort"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/suppress"
)

// WindowGroupState 是单条规则下某个分组键的窗口原始状态：
// 窗口内保留的全部事件（按全序）。部分匹配链可由事件经 DP 重算，无需持久化。
type WindowGroupState struct {
	Key    string
	Events []event.Event
}

// DetectorState 是单条规则检测器的可快照状态：
// 当前规则内容与版本、永久去重指纹集合、各分组窗口事件。
type DetectorState struct {
	Rule    rule.Rule
	Version int
	Fired   []string // 已告警的规范序列指纹（永久保留，防跨重启重复告警）
	Groups  []WindowGroupState
}

// ExportState 深拷贝导出单个检测器状态。调用方持有引擎级锁。
func (d *Detector) ExportState() DetectorState {
	d.mu.Lock()
	defer d.mu.Unlock()

	fired := make([]string, 0, len(d.fired))
	for fp := range d.fired {
		fired = append(fired, fp)
	}

	groups := make([]WindowGroupState, 0, len(d.win.groups))
	for key, g := range d.win.groups {
		evs := make([]event.Event, 0, len(g.events))
		for _, te := range g.events {
			evs = append(evs, te.ev.Clone())
		}
		groups = append(groups, WindowGroupState{Key: key, Events: evs})
	}
	return DetectorState{
		Rule:    d.rv.Content,
		Version: d.rv.Version,
		Fired:   fired,
		Groups:  groups,
	}
}

// restoreDetector 用快照状态构造一个等价检测器。
//
// 关键：窗口事件原样装载，**不做重枚举**——导出时刻已完成的序列已记录在
// Fired 指纹集合中，未凑齐的部分链由事件在下次 Observe 的全量 DP 中重算。
// 因此恢复后既不会重复告警，也不会漏掉重启后才凑齐的序列。
func restoreDetector(st DetectorState) *Detector {
	win := newRuleWindow(st.Rule)
	for _, g := range st.Groups {
		gs := &groupState{key: g.Key, events: make([]timedEvent, 0, len(g.Events))}
		for _, ev := range g.Events {
			cp := ev.Clone()
			gs.events = append(gs.events, timedEvent{id: cp.ID, at: cp.OccurredAt, ev: cp})
		}
		win.groups[g.Key] = gs
	}
	fired := make(map[string]struct{}, len(st.Fired))
	for _, fp := range st.Fired {
		fired[fp] = struct{}{}
	}
	return &Detector{
		rv:    rule.VersionedRule{Content: st.Rule, Version: st.Version},
		win:   win,
		fired: fired,
	}
}

// EngineState 是整个关联引擎的可快照状态。
type EngineState struct {
	Watermark       time.Time
	AllowedLateness time.Duration
	Suppression     rule.SuppressionConfig
	Suppress        suppress.State
	RuleOrder       []string // 规则评估的确定性顺序
	Rules           []DetectorState
	Pending         []event.Event // 已缓冲但尚未排空的事件
}

// ExportState 导出引擎当下的完整运行状态（深拷贝，可脱离引擎长期持有）。
//
// 并发语义：仅在"复制内存中的状态"这一短暂窗口内持有引擎读锁；快照返回后
// 的 JSON 序列化、磁盘写入都在锁外进行，因此反复或周期性导出不会卡住进行中
// 的摄取，也不会让引擎内存占用随导出次数增长（每次导出都是独立拷贝）。
func (e *Engine) ExportState() EngineState {
	e.mu.RLock()
	defer e.mu.RUnlock()

	st := EngineState{
		Watermark:       e.watermark,
		AllowedLateness: e.AllowedLateness,
		Suppression:     e.suppression,
		Suppress:        e.suppressor.ExportState(),
		RuleOrder:       append([]string{}, e.ruleOrder...),
		Rules:           make([]DetectorState, 0, len(e.ruleOrder)),
		Pending:         make([]event.Event, 0, len(e.pending)),
	}
	for _, rid := range e.ruleOrder {
		st.Rules = append(st.Rules, e.rules[rid].ExportState())
	}
	for _, pe := range e.pending {
		st.Pending = append(st.Pending, pe.ev.Clone())
	}
	return st
}

// RestoreState 用快照状态覆盖引擎内部状态（深拷贝入参）。
//
// 恢复后引擎与"从未重启"在可观测结论上等价：
//   - 水印、AllowedLateness、抑制桶、待排空事件原样恢复；
//   - 各规则以快照中的规则内容与版本重建（规则热更新版本随快照演进）；
//   - 窗口事件原样装载但不重枚举，已告警指纹永久保留 => 不重；
//   - 未凑齐的部分链由后续事件经全量 DP 重算补齐 => 不漏。
func (e *Engine) RestoreState(st EngineState) error {
	for _, ds := range st.Rules {
		if err := ds.Rule.Validate(); err != nil {
			return err
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	rules := make(map[string]*Detector, len(st.Rules))
	order := append([]string{}, st.RuleOrder...)
	if len(order) == 0 {
		// 兼容缺失 RuleOrder 的快照：以规则 ID 确定序兜底。
		for _, ds := range st.Rules {
			order = append(order, ds.Rule.ID)
		}
		sort.Strings(order)
	}
	for _, ds := range st.Rules {
		rules[ds.Rule.ID] = restoreDetector(ds)
	}

	// 深拷贝 pending，避免与入参共享底层数组。
	pending := make([]pendingEvent, 0, len(st.Pending))
	for _, ev := range st.Pending {
		pending = append(pending, pendingEvent{ev: ev.Clone()})
	}

	suppCfg := st.Suppression
	if suppCfg.QuietFor == 0 {
		suppCfg = rule.DefaultSuppression()
	}
	sup := suppress.New(st.Suppress.QuietFor, st.Suppress.MaxOccurrences)
	sup.RestoreState(st.Suppress)

	e.rules = rules
	e.ruleOrder = order
	e.suppression = suppCfg
	e.suppressor = sup
	e.pending = pending
	e.watermark = st.Watermark
	e.AllowedLateness = st.AllowedLateness
	return nil
}
