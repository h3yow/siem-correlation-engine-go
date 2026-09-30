package correlate

import (
	"fmt"
	"sort"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

// 本文件负责引擎领域模型（event.Event / rule.Rule）与快照持久化形态
// （snapshot.EventState / snapshot.RuleDef）之间的确定性双向转换。
//
// 严重级别刻意以名称字符串而非枚举序号持久化：未来版本即使调整枚举顺序
// 或新增级别，旧快照仍能被正确解读，不会默默映射成错误级别。

func eventToState(e event.Event) snapshot.EventState {
	var attrs map[string]string
	if len(e.Attributes) > 0 {
		attrs = make(map[string]string, len(e.Attributes))
		for k, v := range e.Attributes {
			attrs[k] = v
		}
	}
	return snapshot.EventState{
		ID:         e.ID,
		OccurredAt: e.OccurredAt.UTC(),
		Source:     e.Source,
		EventType:  e.EventType,
		SrcHost:    e.SrcHost,
		DstHost:    e.DstHost,
		SrcIP:      e.SrcIP,
		DstIP:      e.DstIP,
		User:       e.User,
		Action:     e.Action,
		Status:     e.Status,
		Severity:   e.Severity.String(),
		Attributes: attrs,
		Raw:        e.Raw,
		RawFormat:  e.RawFormat,
	}
}

func stateToEvent(s snapshot.EventState) event.Event {
	var attrs map[string]string
	if len(s.Attributes) > 0 {
		attrs = make(map[string]string, len(s.Attributes))
		for k, v := range s.Attributes {
			attrs[k] = v
		}
	}
	return event.Event{
		ID:         s.ID,
		OccurredAt: s.OccurredAt.UTC(),
		Source:     s.Source,
		EventType:  s.EventType,
		SrcHost:    s.SrcHost,
		DstHost:    s.DstHost,
		SrcIP:      s.SrcIP,
		DstIP:      s.DstIP,
		User:       s.User,
		Action:     s.Action,
		Status:     s.Status,
		Severity:   parseSeverityName(s.Severity),
		Attributes: attrs,
		Raw:        s.Raw,
		RawFormat:  s.RawFormat,
	}
}

// parseSeverityName 把快照里的级别名称还原为枚举；无法识别的旧/新名称
// 统一落到 SeverityUnknown 而不是乱序映射，保证语义安全。
func parseSeverityName(name string) event.Severity {
	switch name {
	case "info":
		return event.SeverityInfo
	case "low":
		return event.SeverityLow
	case "medium":
		return event.SeverityMedium
	case "high":
		return event.SeverityHigh
	case "critical":
		return event.SeverityCritical
	default:
		return event.SeverityUnknown
	}
}

func ruleToDef(r rule.Rule) snapshot.RuleDef {
	ps := make([]snapshot.MatchDef, len(r.Pattern))
	for i, m := range r.Pattern {
		ps[i] = snapshot.MatchDef{
			Source: m.Source, EventType: m.EventType, Action: m.Action,
			User: m.User, SrcIP: m.SrcIP, DstIP: m.DstIP,
		}
	}
	return snapshot.RuleDef{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Severity:    r.Severity.String(),
		Pattern:     ps,
		Window:      snapshot.DurationJSON(r.Window),
		MaxGap:      snapshot.DurationJSON(r.MaxGap),
		GroupBy:     r.GroupBy,
	}
}

func defToRule(d snapshot.RuleDef) rule.Rule {
	ps := make([]rule.Match, len(d.Pattern))
	for i, m := range d.Pattern {
		ps[i] = rule.Match{
			Source: m.Source, EventType: m.EventType, Action: m.Action,
			User: m.User, SrcIP: m.SrcIP, DstIP: m.DstIP,
		}
	}
	return rule.Rule{
		ID:          d.ID,
		Name:        d.Name,
		Description: d.Description,
		Severity:    parseSeverityName(d.Severity),
		Pattern:     ps,
		Window:      time.Duration(d.Window),
		MaxGap:      time.Duration(d.MaxGap),
		GroupBy:     d.GroupBy,
	}
}

// sortedFired 以确定性顺序导出已告警指纹集合。
func sortedFired(fired map[string]struct{}) []string {
	out := make([]string, 0, len(fired))
	for k := range fired {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// errSnapshotState 包装状态恢复时的结构性错误。
func errSnapshotState(format string, args ...any) error {
	return fmt.Errorf("snapshot: invalid state: "+format, args...)
}
