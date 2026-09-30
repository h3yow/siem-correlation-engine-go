package correlate

import (
	"sort"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
)

// chain 记录一条按全序排列、匹配 Pattern[0..k] 的事件链。
type chain struct {
	eventIDs []string
	times    []time.Time
}

// WindowState 是某条规则在某个分组键上的窗口状态快照（可打印、可解释）。
type WindowState struct {
	RuleID    string
	GroupKey  string
	EventIDs  []string // 当前窗内保留的事件（按全序排序）
	Times     []time.Time
	Partials  []PartialSnapshot
	Watermark time.Time
}

// PartialSnapshot 是部分匹配链的可打印快照。
type PartialSnapshot struct {
	PatternIndex int // 该链已匹配到 Pattern 的末位下标（0 起）
	EventIDs     []string
}

// ruleWindow 维护一条规则在所有分组键上的窗口事件缓冲。
//
// 乱序安全的关键：窗口只负责保存"全序事件"，每次 add 后对窗内事件
// 重新枚举所有可完成模式的序列。这样无论事件按什么顺序到达，只要
// 完整序列的全部事件都已进入窗口，就一定被发现（不漏）；是否重复
// 告警由 Detector 的永久指纹集合决定（不重）。
type ruleWindow struct {
	rule   rule.Rule
	groups map[string]*groupState
}

// groupState 维护单个分组键内的全序事件缓冲。
type groupState struct {
	key    string
	events []timedEvent
}

type timedEvent struct {
	id string
	at time.Time
	ev event.Event
}

func newRuleWindow(r rule.Rule) *ruleWindow {
	return &ruleWindow{rule: r, groups: map[string]*groupState{}}
}

func (w *ruleWindow) group(key string) *groupState {
	g := w.groups[key]
	if g == nil {
		g = &groupState{key: key}
		w.groups[key] = g
	}
	return g
}

// fingerprint 是有序事件序列的确定性指纹：同一事件序列 => 同一指纹。
func fingerprint(eventIDs []string) string {
	return strings.Join(eventIDs, ">")
}

// matchOutcome 描述一次完整命中（由 Detector 做跨窗口去重）。
type matchOutcome struct {
	eventIDs    []string
	times       []time.Time
	groupKey    string
	fingerprint string
}

// add 向窗口插入事件并对窗内全序事件重算可完成序列。
//
// 不漏不重的关键设计：
//   - 插入后对窗内事件做全量 DP 重枚举，因此任何位置的迟到事件
//     （哪怕是序列中间事件）补齐序列时都会被发现，保证不漏；
//   - 以"末事件"为每个命中结论的身份锚点：对同一末事件，选取时间上
//     最早可行的前序链作为规范序列。序列的指纹因此在跨轮次重放、
//     乱序插入时保持稳定，配合 Detector 的永久指纹集合保证不重复告警。
func (w *ruleWindow) add(e event.Event, prevFired map[string]struct{}) []matchOutcome {
	groupKey, ok := w.rule.GroupValue(e)
	if !ok {
		// 规则要求分组但该事件缺少分组维度，无法参与该规则。
		return nil
	}
	g := w.group(groupKey)

	te := timedEvent{id: e.ID, at: e.OccurredAt, ev: e}

	// 摄取层已做 (format,raw) 幂等去重；这里再加一道引擎层保险：同一事件
	// ID 在同一分组窗口内只保留一份。重复投递（含跨进程恢复后上游重放）
	// 因此不会产生重复窗口条目、不会虚增抑制计数，也不参与重复枚举。
	for i := range g.events {
		if g.events[i].id == te.id {
			return nil
		}
	}

	pos := sort.Search(len(g.events), func(i int) bool {
		if g.events[i].at.Equal(te.at) {
			return g.events[i].id >= te.id
		}
		return g.events[i].at.After(te.at)
	})
	g.events = append(g.events, timedEvent{})
	copy(g.events[pos+1:], g.events[pos:])
	g.events[pos] = te

	return w.enumerate(g, groupKey, prevFired)
}

// enumerate 在窗内事件上做动态规划。
//
// dp[k] 对每个"末尾事件"只保留最早可行的一条链：由于事件按全序扫描，
// 同一末尾的候选链只保留第一条（即最早生成、前序也最早的链）。
// 这样每个末事件在最后一个 Pattern 位置上至多对应一条规范序列，
// 从根本上消除"同一攻击在窗内组合爆炸"的问题。
func (w *ruleWindow) enumerate(g *groupState, groupKey string, prevFired map[string]struct{}) []matchOutcome {
	n := w.rule.PatternLen()
	evs := g.events
	// dp[k]: tailEventID -> 该末尾事件上的最早可行链。
	dp := make([]map[string]chain, n)
	for k := range dp {
		dp[k] = map[string]chain{}
	}

	for idx, te := range evs {
		// Pattern[0]：播种新链（每个事件在位置 0 只有一条链）。
		if w.rule.Pattern[0].Matches(te.ev) {
			dp[0][te.id] = chain{
				eventIDs: []string{te.id},
				times:    []time.Time{te.at},
			}
		}
		for k := 1; k < n; k++ {
			if !w.rule.Pattern[k].Matches(te.ev) {
				continue
			}
			// 在所有排在当前事件之前、且匹配 Pattern[k-1] 的末尾链中，
			// 选首事件最早（其次末事件最早）的一条作为规范前序。
			var best *chain
			for tailID, prev := range dp[k-1] {
				pi := indexOf(evs, tailID)
				if pi < 0 || pi >= idx {
					continue
				}
				if te.at.Sub(prev.times[0]) > w.rule.Window {
					continue
				}
				prevLast := prev.times[len(prev.times)-1]
				if w.rule.MaxGap > 0 && te.at.Sub(prevLast) > w.rule.MaxGap {
					continue
				}
				if best == nil || chainLess(prev, *best) {
					c := prev
					best = &c
				}
			}
			if best != nil {
				dp[k][te.id] = chain{
					eventIDs: append(append([]string{}, best.eventIDs...), te.id),
					times:    append(append([]time.Time{}, best.times...), te.at),
				}
			}
		}
	}

	// 按末事件 ID 确定性输出所有未告警过的完整规范序列。
	tailIDs := make([]string, 0, len(dp[n-1]))
	for id := range dp[n-1] {
		tailIDs = append(tailIDs, id)
	}
	sort.Strings(tailIDs)
	var out []matchOutcome
	for _, id := range tailIDs {
		c := dp[n-1][id]
		fp := fingerprint(c.eventIDs)
		if _, dup := prevFired[fp]; dup {
			continue
		}
		out = append(out, matchOutcome{
			eventIDs:    append([]string{}, c.eventIDs...),
			times:       append([]time.Time{}, c.times...),
			groupKey:    groupKey,
			fingerprint: fp,
		})
	}
	return out
}

// chainLess 比较两条链：首事件更早者更小；首事件相同则逐位比较。
func chainLess(a, b chain) bool {
	if !a.times[0].Equal(b.times[0]) {
		return a.times[0].Before(b.times[0])
	}
	for i := 0; i < len(a.eventIDs) && i < len(b.eventIDs); i++ {
		if !a.times[i].Equal(b.times[i]) {
			return a.times[i].Before(b.times[i])
		}
		if a.eventIDs[i] != b.eventIDs[i] {
			return a.eventIDs[i] < b.eventIDs[i]
		}
	}
	return len(a.eventIDs) < len(b.eventIDs)
}

// indexOf 返回事件 ID 在切片中的下标，不存在返回 -1。
func indexOf(evs []timedEvent, id string) int {
	for i := range evs {
		if evs[i].id == id {
			return i
		}
	}
	return -1
}

// advance 以水印 t 淘汰过期事件：早于 t-Window 的事件不可能再成为
// 合法序列的一员（任何包含它的序列首跨度都已超窗）。
func (w *ruleWindow) advance(t time.Time) {
	cutoff := t.Add(-w.rule.Window)
	for _, g := range w.groups {
		kept := g.events[:0]
		for _, te := range g.events {
			if !te.at.Before(cutoff) {
				kept = append(kept, te)
			}
		}
		g.events = kept
	}
}

// snapshot 产出全部非空分组的可打印状态快照，并展示部分匹配链。
func (w *ruleWindow) snapshot(watermark time.Time) []WindowState {
	out := make([]WindowState, 0, len(w.groups))
	keys := make([]string, 0, len(w.groups))
	for k := range w.groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := w.groups[k]
		if len(g.events) == 0 {
			continue
		}
		st := WindowState{RuleID: w.rule.ID, GroupKey: k, Watermark: watermark}
		for _, te := range g.events {
			st.EventIDs = append(st.EventIDs, te.id)
			st.Times = append(st.Times, te.at)
		}
		// 快照里展示部分匹配链：现场做一次受限 DP（不依赖 fired 集合）。
		for _, c := range partialChains(w.rule, g.events) {
			st.Partials = append(st.Partials, PartialSnapshot{
				PatternIndex: len(c.eventIDs) - 1,
				EventIDs:     append([]string{}, c.eventIDs...),
			})
		}
		out = append(out, st)
	}
	return out
}

// partialChains 返回各 Pattern 位置上的代表性部分链（用于日志展示）。
// 与 enumerate 相同的"每末尾保留最早可行链"规则，保证快照可解释且稳定。
func partialChains(r rule.Rule, evs []timedEvent) []chain {
	n := r.PatternLen()
	dp := make([]map[string]chain, n)
	for k := range dp {
		dp[k] = map[string]chain{}
	}
	for idx, te := range evs {
		if r.Pattern[0].Matches(te.ev) {
			dp[0][te.id] = chain{eventIDs: []string{te.id}, times: []time.Time{te.at}}
		}
		for k := 1; k < n; k++ {
			if !r.Pattern[k].Matches(te.ev) {
				continue
			}
			var best *chain
			for tailID, prev := range dp[k-1] {
				pi := indexOf(evs, tailID)
				if pi < 0 || pi >= idx {
					continue
				}
				if te.at.Sub(prev.times[0]) > r.Window {
					continue
				}
				prevLast := prev.times[len(prev.times)-1]
				if r.MaxGap > 0 && te.at.Sub(prevLast) > r.MaxGap {
					continue
				}
				if best == nil || chainLess(prev, *best) {
					c := prev
					best = &c
				}
			}
			if best != nil {
				dp[k][te.id] = chain{
					eventIDs: append(append([]string{}, best.eventIDs...), te.id),
					times:    append(append([]time.Time{}, best.times...), te.at),
				}
			}
		}
	}
	// 每个位置最多展示 5 条链，避免日志爆炸。
	var out []chain
	for k := 0; k < n; k++ {
		ids := make([]string, 0, len(dp[k]))
		for id := range dp[k] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for i, id := range ids {
			if i >= 5 {
				break
			}
			out = append(out, dp[k][id])
		}
	}
	return out
}
