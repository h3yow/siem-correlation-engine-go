package window

import (
	"sort"
	"sync"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/alert"
	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
	"github.com/h3yow/siem-correlation-engine-go/pkg/rule"
)

// Match 是一次成功关联的结果，携带可解释的完整证据链。
type Match struct {
	Fingerprint string
	RuleID      string
	RuleVersion int
	Partition   string
	Events      []*event.Event // 按规则步骤顺序排列的证据事件
	WindowStart time.Time
	WindowEnd   time.Time
	MatchedAt   time.Time // 判定时刻（处理时间）
}

// AddResult 是一次事件加入窗口的结果。
type AddResult struct {
	Matches     []Match
	DroppedLate bool // 事件晚于水位线容忍度，被拒绝参与关联
	Evicted     int  // 本次淘汰的过期事件数
}

// PartitionState 以 (规则, 分区) 为维度保存事件时间窗口状态。
type PartitionState struct {
	RuleID    string
	Partition string
	Events    []*event.Event // 按 (事件时间, 摄取序号) 排序
	MaxTS     time.Time      // 已观察到的最大事件时间
	Watermark time.Time      // MaxTS - lateness，早于此时间的事件视为迟到
	Fired     map[string]bool
}

// Manager 维护所有规则 × 分区的窗口状态。
type Manager struct {
	mu     sync.Mutex
	states map[string]map[string]*PartitionState // ruleID -> partition -> state
}

func NewManager() *Manager {
	return &Manager{states: map[string]map[string]*PartitionState{}}
}

// Add 把事件（允许乱序）加入对应窗口并计算新产生的关联。
// 不变量：只有包含本次新事件的完整链才可能是"新"关联，
// 因而既不会漏告警，也不会对历史链重复告警。
func (m *Manager) Add(r *rule.Rule, partition string, ev *event.Event, now time.Time) AddResult {
	m.mu.Lock()
	defer m.mu.Unlock()

	parts := m.states[r.ID]
	if parts == nil {
		parts = map[string]*PartitionState{}
		m.states[r.ID] = parts
	}
	st := parts[partition]
	if st == nil {
		st = &PartitionState{
			RuleID: r.ID, Partition: partition,
			Fired: map[string]bool{},
		}
		parts[partition] = st
	}

	res := AddResult{}
	if !st.MaxTS.IsZero() && ev.Timestamp.Before(st.Watermark) {
		res.DroppedLate = true
		return res
	}

	st.Events = insertSorted(st.Events, ev)
	if ev.Timestamp.After(st.MaxTS) {
		st.MaxTS = ev.Timestamp
	}
	st.Watermark = st.MaxTS.Add(-r.Lateness)
	st.Events, res.Evicted = evictBefore(st.Events, st.MaxTS.Add(-(r.Window + r.Lateness)))

	res.Matches = m.findNewMatches(r, st, ev, now)
	return res
}

// maxNewChainsPerAdd 限制单次加入最多新产生的证据链数，防止组合爆炸。
const maxNewChainsPerAdd = 256

// findNewMatches 在当前窗口的全量有序事件上枚举所有满足序列条件、
// 跨度不超过 Window 的完整证据链（确定性 DFS），只有新指纹才触发。
//
// 语义：在水位线容忍度内，任何到达顺序下，触发指纹的并集都收敛为
// 同一结果——乱序/并发不会改变最终告警集合，只可能改变"何时"被发现。
func (m *Manager) findNewMatches(r *rule.Rule, st *PartitionState, ev *event.Event, now time.Time) []Match {
	evs := st.Events
	n := len(r.Sequence)

	var chains [][]*event.Event
	chain := make([]*event.Event, n)
	var dfs func(step, from int)
	dfs = func(step, from int) {
		if len(chains) >= maxNewChainsPerAdd {
			return
		}
		if step == n {
			cp := append([]*event.Event(nil), chain...)
			chains = append(chains, cp)
			return
		}
		for i := from; i < len(evs); i++ {
			if !r.MatchStep(evs[i], step) {
				continue
			}
			// 窗口跨度约束：相对链首事件（step 0）。
			if step > 0 && evs[i].Timestamp.Sub(chain[0].Timestamp) > r.Window {
				break // 后续事件时间更晚，不可能满足
			}
			chain[step] = evs[i]
			dfs(step+1, i+1)
			chain[step] = nil
		}
	}
	dfs(0, 0)

	out := make([]Match, 0, len(chains))
	for _, ch := range chains {
		fp := alert.FingerprintFor(r.ID, st.Partition, ch)
		if st.Fired[fp] {
			continue
		}
		st.Fired[fp] = true
		out = append(out, Match{
			Fingerprint: fp,
			RuleID:      r.ID,
			RuleVersion: r.Version,
			Partition:   st.Partition,
			Events:      ch,
			WindowStart: ch[0].Timestamp,
			WindowEnd:   ch[n-1].Timestamp,
			MatchedAt:   now,
		})
	}
	return out
}

// eventLess 定义确定性的事件时间排序：(时间戳, 摄取序号, ID)。
func eventLess(a, b *event.Event) bool {
	if !a.Timestamp.Equal(b.Timestamp) {
		return a.Timestamp.Before(b.Timestamp)
	}
	if a.IngestSeq != b.IngestSeq {
		return a.IngestSeq < b.IngestSeq
	}
	return a.ID < b.ID
}

func insertSorted(evs []*event.Event, ev *event.Event) []*event.Event {
	i := sort.Search(len(evs), func(i int) bool { return eventLess(ev, evs[i]) })
	evs = append(evs, nil)
	copy(evs[i+1:], evs[i:])
	evs[i] = ev
	return evs
}

func evictBefore(evs []*event.Event, horizon time.Time) ([]*event.Event, int) {
	cut := sort.Search(len(evs), func(i int) bool { return !evs[i].Timestamp.Before(horizon) })
	if cut == 0 {
		return evs, 0
	}
	return append([]*event.Event(nil), evs[cut:]...), cut
}

// WatermarkOf 返回 (规则, 分区) 当前（事件加入前）的水位线。
func (m *Manager) WatermarkOf(ruleID, partition string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if parts, ok := m.states[ruleID]; ok {
		if st, ok := parts[partition]; ok {
			return st.Watermark
		}
	}
	return time.Time{}
}

// DropRule 移除某条规则的全部窗口状态（规则被删除时调用）。
func (m *Manager) DropRule(ruleID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, ruleID)
}

// AdvanceWatermark 按处理时间推进并彻底淘汰长期空闲的分区状态。
func (m *Manager) AdvanceWatermark(rules []*rule.Rule, now time.Time) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var evicted []string
	for _, r := range rules {
		parts := m.states[r.ID]
		for pkey, st := range parts {
			horizon := now.Add(-(r.Window + r.Lateness + r.Lateness))
			if st.MaxTS.Before(horizon) {
				delete(parts, pkey)
				evicted = append(evicted, r.ID+"/"+pkey)
			}
		}
		if len(parts) == 0 {
			delete(m.states, r.ID)
		}
	}
	return evicted
}

// Snapshot 返回某规则当前全部窗口状态副本（测试与可解释输出用）。
func (m *Manager) Snapshot(ruleID string) []PartitionState {
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := m.states[ruleID]
	out := make([]PartitionState, 0, len(parts))
	for _, st := range parts {
		cp := PartitionState{
			RuleID:    st.RuleID,
			Partition: st.Partition,
			MaxTS:     st.MaxTS,
			Watermark: st.Watermark,
			Fired:     map[string]bool{},
			Events:    append([]*event.Event(nil), st.Events...),
		}
		for fp := range st.Fired {
			cp.Fired[fp] = true
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Partition < out[j].Partition })
	return out
}
