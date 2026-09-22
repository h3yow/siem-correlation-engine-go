package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/suppress"
)

// EngineResult 汇总一次批处理的告警与拒绝。
type EngineResult struct {
	Alerts   []alert.Alert
	Rejected []event.RejectedRecord
}

// pendingEvent 是尚未进入检测器的、按事件时间缓冲的事件。
type pendingEvent struct {
	ev event.Event
}

// Engine 是关联引擎：按事件时间确定性排序、驱动全部规则检测器、
// 管理水印淘汰、处理规则热更新并对接抑制器。
//
// 乱序模型：
//   - 摄取事件先进缓冲；ProcessBatch / drain 时按全序 (OccurredAt, ID) 稳定排序，
//     因此无论到达顺序与并发调度如何，进入检测器的事件序列完全确定 => 结论一致。
//   - 水印 = 已观察到的最大事件时间。允许 AllowedLateness 内的迟到事件正常参与；
//     超过水印 AllowedLateness 的过迟事件以 too_late 拒绝（不静默丢弃）。
type Engine struct {
	rules           map[string]*Detector
	ruleOrder       []string // 规则迭代的确定性顺序
	suppression     rule.SuppressionConfig
	suppressor      *suppress.Suppressor
	pending         []pendingEvent
	watermark       time.Time
	AllowedLateness time.Duration
}

// NewEngine 构造引擎。
func NewEngine(suppressCfg rule.SuppressionConfig, allowedLateness time.Duration) *Engine {
	if suppressCfg.QuietFor == 0 {
		suppressCfg = rule.DefaultSuppression()
	}
	return &Engine{
		rules:           map[string]*Detector{},
		suppression:     suppressCfg,
		suppressor:      suppress.New(suppressCfg.QuietFor, suppressCfg.MaxOccurrences),
		AllowedLateness: allowedLateness,
	}
}

// UpsertRule 运行期新增或更新规则。
//
// 已存在的同 ID 规则走 ReplaceRule：保留全部窗口状态与已告警指纹，
// 规则更新不会丢失积累状态，也不会重复触发已产生的告警。
func (e *Engine) UpsertRule(r rule.Rule, version int) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if d, ok := e.rules[r.ID]; ok {
		d.ReplaceRule(r, version)
		return nil
	}
	e.rules[r.ID] = NewDetector(rule.VersionedRule{Content: r, Version: version})
	e.ruleOrder = append(e.ruleOrder, r.ID)
	sort.Strings(e.ruleOrder)
	return nil
}

// BufferEvent 仅缓冲一个摄取到的事件（乱序安全），不做检测。
func (e *Engine) BufferEvent(ev event.Event) {
	e.pending = append(e.pending, pendingEvent{ev: ev})
}

// ProcessEvent 缓冲并立即排空处理（适合流式逐条调用），返回新告警与可能的拒绝。
func (e *Engine) ProcessEvent(ev event.Event) ([]alert.Alert, *event.RejectedRecord) {
	e.BufferEvent(ev)
	res := e.drain()
	if len(res.Rejected) > 0 {
		rj := res.Rejected[len(res.Rejected)-1]
		return res.Alerts, &rj
	}
	return res.Alerts, nil
}

// ProcessBatch 批量投递：缓冲后按事件全序统一排空。
// 同一批事件无论以何种到达顺序进入，结论完全一致、可复现。
func (e *Engine) ProcessBatch(evs []event.Event) EngineResult {
	for _, ev := range evs {
		e.pending = append(e.pending, pendingEvent{ev: ev})
	}
	return e.drain()
}

// ProcessBatchShuffled 先以固定种子打乱到达顺序再批量处理，
// 用于验证乱序到达不改变结论（结论应与 ProcessBatch 完全相同）。
func (e *Engine) ProcessBatchShuffled(evs []event.Event, seed int64) EngineResult {
	shuffled := deterministicShuffle(append([]event.Event{}, evs...), seed)
	return e.ProcessBatch(shuffled)
}

// drain 将缓冲按全序排序，做迟到判定，推进水印并驱动全部检测器。
func (e *Engine) drain() EngineResult {
	var res EngineResult
	if len(e.pending) == 0 {
		return res
	}

	// 全序排序：(OccurredAt, ID)。ID 唯一，故为严格全序。
	sort.SliceStable(e.pending, func(i, j int) bool {
		a, b := e.pending[i].ev, e.pending[j].ev
		if !a.OccurredAt.Equal(b.OccurredAt) {
			return a.OccurredAt.Before(b.OccurredAt)
		}
		return a.ID < b.ID
	})

	ordered := e.pending
	e.pending = nil

	for _, pe := range ordered {
		ev := pe.ev

		// 迟到判定：事件时间早于 水印-AllowedLateness，视为过迟，明确拒绝。
		if !e.watermark.IsZero() && e.AllowedLateness > 0 {
			limit := e.watermark.Add(-e.AllowedLateness)
			if ev.OccurredAt.Before(limit) {
				res.Rejected = append(res.Rejected, event.RejectedRecord{
					Raw:    ev.Raw,
					Format: ev.RawFormat,
					Reason: event.Reason("too_late"),
					Detail: "event " + ev.ID + " at " + ev.OccurredAt.Format(time.RFC3339) +
						" is later than watermark " + e.watermark.Format(time.RFC3339) +
						" minus allowed lateness " + e.AllowedLateness.String(),
				})
				continue
			}
		}

		// 水印取已观察最大事件时间（仅在事件被接受参与时推进）。
		if ev.OccurredAt.After(e.watermark) {
			e.watermark = ev.OccurredAt
		}

		// 规则按确定性顺序评估；同一事件序列在每个规则下至多产生一条告警（指纹去重）。
		for _, rid := range e.ruleOrder {
			d := e.rules[rid]
			fired := d.Observe(ev, e.watermark)
			for _, a := range fired {
				groupDim, groupVal := ruleGroupDimAndValue(d, ev)
				a.AggregateKey = rule.AggregateKey(e.suppression, a.RuleID, groupDim, groupVal)
				a = e.suppressor.Apply(a, e.watermark)
				res.Alerts = append(res.Alerts, a)
			}
		}
	}

	// 告警输出也按确定性键排序，保证可复现的对比。
	sortAlerts(res.Alerts)
	return res
}

// ruleGroupDimAndValue 取规则分组维度名与该事件对应的分组值。
func ruleGroupDimAndValue(d *Detector, ev event.Event) (dim, value string) {
	r := d.Rule()
	dim = r.GroupBy
	if dim == "" {
		return "", "_"
	}
	v, ok := r.GroupValue(ev)
	if !ok {
		return dim, "_"
	}
	return dim, v
}

// sortAlerts 按 (FirstEventAt, RuleID, DedupKey, Kind) 稳定排序。
func sortAlerts(as []alert.Alert) {
	sort.SliceStable(as, func(i, j int) bool {
		a, b := as[i], as[j]
		if !a.FirstEventAt.Equal(b.FirstEventAt) {
			return a.FirstEventAt.Before(b.FirstEventAt)
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.DedupKey != b.DedupKey {
			return a.DedupKey < b.DedupKey
		}
		return a.Kind < b.Kind
	})
}

// Watermark 返回当前水印。
func (e *Engine) Watermark() time.Time { return e.watermark }

// Detectors 暴露检测器快照（测试/日志用）。
func (e *Engine) Detectors() map[string]*Detector { return e.rules }

// DumpState 以确定性顺序打印全部规则窗口状态：水印、保留事件、部分匹配链，
// 用于单测日志和"判定依据可解释"。
func (e *Engine) DumpState() string {
	var b strings.Builder
	fmt.Fprintf(&b, "==== engine state ====\n")
	fmt.Fprintf(&b, "watermark=%s allowed_lateness=%s pending=%d\n",
		fmtTime(e.watermark), e.AllowedLateness, len(e.pending))
	for _, rid := range e.ruleOrder {
		d := e.rules[rid]
		r := d.Rule()
		snaps := d.SnapshotWithWatermark(e.watermark)
		fmt.Fprintf(&b, "[rule] id=%s v%d name=%q window=%s max_gap=%s group_by=%s groups=%d\n",
			rid, d.RuleVersion(), r.Name, r.Window, r.MaxGap, groupDimName(r.GroupBy), len(snaps))
		for _, s := range snaps {
			fmt.Fprintf(&b, "  [group] key=%s events=%d\n", s.GroupKey, len(s.EventIDs))
			for i, id := range s.EventIDs {
				fmt.Fprintf(&b, "    event[%d] id=%s at=%s\n", i, id, fmtTime(s.Times[i]))
			}
			for _, p := range s.Partials {
				fmt.Fprintf(&b, "    partial pattern[0..%d] %v\n", p.PatternIndex, p.EventIDs)
			}
		}
	}
	for _, bk := range e.suppressor.Buckets() {
		fmt.Fprintf(&b, "[suppress] key=%s occurrences=%d quiet_until=%s\n",
			bk.AggregateKey, bk.OccurrenceCnt, fmtTime(bk.QuietUntil))
	}
	fmt.Fprintf(&b, "======================\n")
	return b.String()
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// deterministicShuffle 使用固定种子的 LCG 做确定性 Fisher-Yates 洗牌。
func deterministicShuffle(evs []event.Event, seed int64) []event.Event {
	state := seed
	next := func() int {
		// Numerical Recipes LCG 常数。
		state = state*6364136223846793005 + 1442695040888963407
		return int(uint64(state) >> 33)
	}
	for i := len(evs) - 1; i > 0; i-- {
		j := next() % (i + 1)
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs
}
