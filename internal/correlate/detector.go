package correlate

import (
	"fmt"
	"sync"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

// Detector 对单条规则维护全部分组的滑动窗口并产出告警。
//
// 去重：完整序列的确定性指纹永久记录在 fired 中（即使窗口状态过期淘汰，
// 指纹也保留），保证同一事件序列不会因窗口滚动/乱序重放而重复告警。
type Detector struct {
	mu    sync.Mutex
	rv    rule.VersionedRule
	win   *ruleWindow
	fired map[string]struct{}
}

// NewDetector 为一条版本化规则构造检测器。
func NewDetector(rv rule.VersionedRule) *Detector {
	return &Detector{
		rv:    rv,
		win:   newRuleWindow(rv.Content),
		fired: map[string]struct{}{},
	}
}

// ReplaceRule 在运行期替换规则内容。
//
// 关键语义：窗口状态与已告警指纹按 RuleID 原样保留——规则变更不丢失
// 已积累的窗口状态，也不会重复触发已产生的告警。新规则立即生效
// （告警上记录新的 RuleVersion）。
func (d *Detector) ReplaceRule(r rule.Rule, version int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rv = rule.VersionedRule{Content: r, Version: version}
	// 复用已有分组状态：以新规则参数重建窗口容器并迁移 groupState。
	nw := newRuleWindow(r)
	for k, g := range d.win.groups {
		nw.groups[k] = g
	}
	d.win = nw
}

// Observe 向规则投递一个事件（调用方保证按全序投递），返回新产生的告警。
// 每个事件投递前先以事件时间推进水印淘汰过期状态。
func (d *Detector) Observe(e event.Event, watermark time.Time) []alert.Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.win.advance(watermark)
	outcomes := d.win.add(e, d.fired)
	if len(outcomes) == 0 {
		return nil
	}

	var alerts []alert.Alert
	for _, o := range outcomes {
		// 双重保险：窗口枚举已用 fired 剪枝，这里再确认一次。
		if _, seen := d.fired[o.fingerprint]; seen {
			continue
		}
		d.fired[o.fingerprint] = struct{}{}
		alerts = append(alerts, d.buildAlert(o, watermark))
	}
	return alerts
}

// buildAlert 依据命中结果构造带完整证据链与判定依据的告警。
func (d *Detector) buildAlert(o matchOutcome, at time.Time) alert.Alert {
	r := d.rv.Content
	ev := make([]alert.Evidence, len(o.eventIDs))
	for i, id := range o.eventIDs {
		ev[i] = alert.Evidence{
			EventID:    id,
			OccurredAt: o.times[i],
			Source:     r.Pattern[i].Source,
			EventType:  r.Pattern[i].EventType,
			MatchIdx:   i,
			Role:       fmt.Sprintf("pattern[%d]", i),
		}
	}
	reason := fmt.Sprintf(
		"规则 %s v%d: %d 个事件按时间顺序在 %s 窗内匹配全部 %d 个模式位置 (group_by=%s, group=%s); 序列指纹=%s",
		r.ID, d.rv.Version, len(o.eventIDs), r.Window, r.PatternLen(),
		groupDimName(r.GroupBy), o.groupKey, o.fingerprint)
	return alert.FiredAlert(
		r.ID, d.rv.Version, r.Name, r.Severity, ev, o.fingerprint, reason, at,
	)
}

func groupDimName(g string) string {
	if g == "" {
		return "<none>"
	}
	return g
}

// AdvanceWatermark 显式推进水印并淘汰过期状态。
func (d *Detector) AdvanceWatermark(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.win.advance(t)
}

// Snapshot 返回窗口状态快照用于日志。
func (d *Detector) Snapshot() []WindowState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.win.snapshot(time.Time{})
}

// SnapshotWithWatermark 返回带引擎水印的窗口状态快照。
func (d *Detector) SnapshotWithWatermark(wm time.Time) []WindowState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.win.snapshot(wm)
}

// RuleVersion 返回当前规则版本。
func (d *Detector) RuleVersion() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rv.Version
}

// Rule 返回检测器当前规则内容（只读使用）。
func (d *Detector) Rule() rule.Rule {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.rv.Content
}
