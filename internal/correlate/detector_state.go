package correlate

import (
	"sort"

	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// ExportState 在检测器锁内导出可跨进程恢复的全部状态：
// 当前规则内容与版本、永久已告警指纹集合、各分组窗口内保留的事件。
//
// 部分匹配链不导出（窗内事件的确定性派生物，恢复后由 DP 重枚举重建）。
func (d *Detector) ExportState() snapshot.RuleState {
	d.mu.Lock()
	defer d.mu.Unlock()

	st := snapshot.RuleState{
		ID:      d.rv.Content.ID,
		Version: d.rv.Version,
		Rule:    ruleToDef(d.rv.Content),
		Fired:   sortedFired(d.fired),
	}
	keys := make([]string, 0, len(d.win.groups))
	for k := range d.win.groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := d.win.groups[k]
		gs := snapshot.GroupState{Key: k}
		for _, te := range g.events {
			gs.Events = append(gs.Events, eventToState(te.ev))
		}
		st.Groups = append(st.Groups, gs)
	}
	return st
}

// RestoreDetector 从快照状态重建检测器，并校验结构合法性。
//
// 校验失败会返回明确错误而不是带病运行：规则内容必须通过 Validate，
// 且规则 ID 必须与检测器条目 ID 一致（防止错配快照算出错误结论）。
func RestoreDetector(st snapshot.RuleState) (*Detector, error) {
	r := defToRule(st.Rule)
	if err := r.Validate(); err != nil {
		return nil, errSnapshotState("rule %s invalid: %w", st.ID, err)
	}
	if r.ID != st.ID {
		return nil, errSnapshotState("rule entry id %q != rule content id %q", st.ID, r.ID)
	}
	if st.Version < 0 {
		return nil, errSnapshotState("rule %s has negative version %d", st.ID, st.Version)
	}

	d := NewDetector(rule.VersionedRule{Content: r, Version: st.Version})
	d.fired = make(map[string]struct{}, len(st.Fired))
	for _, fp := range st.Fired {
		if fp == "" {
			return nil, errSnapshotState("rule %s: empty fired fingerprint", st.ID)
		}
		d.fired[fp] = struct{}{}
	}

	for _, g := range st.Groups {
		if g.Key == "" {
			return nil, errSnapshotState("rule %s: empty group key", st.ID)
		}
		gs := &groupState{key: g.Key}
		for _, es := range g.Events {
			ev := stateToEvent(es)
			if ev.ID == "" || ev.OccurredAt.IsZero() {
				return nil, errSnapshotState("rule %s group %s: event missing id/time", st.ID, g.Key)
			}
			gs.events = append(gs.events, timedEvent{id: ev.ID, at: ev.OccurredAt, ev: ev})
		}
		// 防御性排序：窗口逻辑依赖事件严格按 (at,id) 全序。
		sort.SliceStable(gs.events, func(i, j int) bool {
			a, b := gs.events[i], gs.events[j]
			if !a.at.Equal(b.at) {
				return a.at.Before(b.at)
			}
			return a.id < b.id
		})
		d.win.groups[g.Key] = gs
	}
	return d, nil
}
