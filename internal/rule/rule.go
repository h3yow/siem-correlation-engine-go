// Package rule 定义关联规则模型与规则版本化变更。
package rule

import (
	"errors"
	"fmt"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// Match 描述规则 Pattern 中的一个事件匹配条件。
//
// 空字符串字段表示通配（不参与约束）。
type Match struct {
	Source    string
	EventType string
	Action    string
	User      string
	SrcIP     string
	DstIP     string
}

// Matches 判断事件是否满足该匹配条件。空字符串字段表示通配。
func (m Match) Matches(e event.Event) bool {
	if m.Source != "" && m.Source != e.Source {
		return false
	}
	if m.EventType != "" && m.EventType != e.EventType {
		return false
	}
	if m.Action != "" && m.Action != e.Action {
		return false
	}
	if m.User != "" && m.User != e.User {
		return false
	}
	if m.SrcIP != "" && m.SrcIP != e.SrcIP {
		return false
	}
	if m.DstIP != "" && m.DstIP != e.DstIP {
		return false
	}
	return true
}

// Rule 是一条基于滑动时间窗的多事件有序关联规则。
//
// 语义：
//   - Pattern 必须按事件 OccurredAt 的时间顺序依次匹配（允许中间夹杂其他事件）。
//   - 序列第一个事件到最后一个事件的时间跨度必须 <= Window。
//   - MaxGap > 0 时，相邻命中事件时间差必须 <= MaxGap（0 表示不约束）。
//   - GroupBy 非空时，序列内事件必须在该维度取值相同（如 src_ip / user / host）。
//   - 同一事件序列（相同有序事件 ID 集合）在任何情况下只告警一次。
type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    event.Severity
	Pattern     []Match
	Window      time.Duration
	MaxGap      time.Duration
	GroupBy     string
}

// PatternLen 返回模式长度。
func (r Rule) PatternLen() int { return len(r.Pattern) }

// Validate 校验规则定义是否合法。
func (r Rule) Validate() error {
	if r.ID == "" {
		return errors.New("rule: id is required")
	}
	if len(r.Pattern) == 0 {
		return fmt.Errorf("rule %s: pattern must not be empty", r.ID)
	}
	if r.Window <= 0 {
		return fmt.Errorf("rule %s: window must be positive", r.ID)
	}
	if r.MaxGap < 0 {
		return fmt.Errorf("rule %s: max_gap must not be negative", r.ID)
	}
	if r.MaxGap > 0 && r.MaxGap > r.Window {
		return fmt.Errorf("rule %s: max_gap must not exceed window", r.ID)
	}
	for i, m := range r.Pattern {
		if m.Source == "" && m.EventType == "" && m.Action == "" {
			return fmt.Errorf("rule %s: pattern[%d] has no constraint", r.ID, i)
		}
	}
	switch r.GroupBy {
	case "", "src_ip", "dst_ip", "user", "src_host", "dst_host":
	default:
		return fmt.Errorf("rule %s: unsupported group_by %q", r.ID, r.GroupBy)
	}
	return nil
}

// VersionedRule 给规则内容绑定一个单调版本号。
//
// 版本号用于：
//  1. 告警上记录 RuleVersion，使判定可复现；
//  2. 规则更新时区分"内容变更"（新版本）与未变更；
//  3. 已积累窗口状态按 RuleID 保留，不因换版本而清空。
type VersionedRule struct {
	Content Rule
	Version int
}

// GroupValue 按 GroupBy 维度取出事件的分组值。
// GroupBy 为空时所有事件归入固定分组 "_"。
func (r Rule) GroupValue(e event.Event) (string, bool) {
	switch r.GroupBy {
	case "":
		return "_", true
	case "src_ip":
		if e.SrcIP == "" {
			return "", false
		}
		return e.SrcIP, true
	case "dst_ip":
		if e.DstIP == "" {
			return "", false
		}
		return e.DstIP, true
	case "user":
		if e.User == "" {
			return "", false
		}
		return e.User, true
	case "src_host":
		if e.SrcHost == "" {
			return "", false
		}
		return e.SrcHost, true
	case "dst_host":
		if e.DstHost == "" {
			return "", false
		}
		return e.DstHost, true
	default:
		return "", false
	}
}
