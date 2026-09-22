package rule

import (
	"fmt"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// Condition 是对单个事件的匹配条件。
type Condition struct {
	Type     string            `json:"type"`
	Source   string            `json:"source,omitempty"`
	Severity []event.Severity  `json:"severity,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
}

// Match 判断事件是否满足该条件：type 精确相等（"*" 表示任意），
// source/severity/attrs 均为"为空即不限制"。
func (c Condition) Match(ev *event.Event) bool {
	if ev == nil {
		return false
	}
	if c.Type != "" && c.Type != "*" && c.Type != ev.Type {
		return false
	}
	if c.Source != "" && c.Source != ev.Source {
		return false
	}
	if len(c.Severity) > 0 {
		hit := false
		for _, sev := range c.Severity {
			if sev == ev.Severity {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for k, want := range c.Attrs {
		if !attrEquals(ev, k, want) {
			return false
		}
	}
	return true
}

// attrEquals 支持特殊键 source/type/subject/severity，其余查 Attrs。
func attrEquals(ev *event.Event, key, want string) bool {
	switch key {
	case "source":
		return ev.Source == want
	case "type":
		return ev.Type == want
	case "subject":
		return ev.Subject == want
	case "severity":
		return string(ev.Severity) == want
	default:
		got, ok := ev.Attrs[key]
		return ok && got == want
	}
}

// Rule 描述一条多事件滑动时间窗关联规则：
// 在 Window 时间内（事件时间语义）出现满足 Sequence 全部条件的事件序列即触发；
// 事件允许乱序到达，按事件时间排序后判定。
type Rule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Window      time.Duration `json:"window"`
	Lateness    time.Duration `json:"lateness"`
	// GroupBy 为分区维度；不同分区窗口状态互不影响。
	GroupBy []string `json:"group_by"`
	// Sequence 为有序条件序列，同一事件不得复用给多个步骤。
	Sequence []Condition `json:"sequence"`
	// DedupWindow: 同一指纹的告警在此事件时间跨度内只产生一次。
	DedupWindow time.Duration `json:"dedup_window"`
	Version     int           `json:"version"`
	Disabled    bool          `json:"disabled"`
}

// Validate 检查规则定义是否合法。
func (r *Rule) Validate() error {
	if r.ID == "" {
		return errRule("rule id is empty")
	}
	if r.Window <= 0 {
		return errRule("rule %s window must be positive", r.ID)
	}
	if len(r.Sequence) == 0 {
		return errRule("rule %s has empty sequence", r.ID)
	}
	for i, c := range r.Sequence {
		if c.Type == "" {
			return errRule("rule %s sequence[%d] missing type", r.ID, i)
		}
	}
	return nil
}

// PartitionKey 计算事件在本规则下的分区键。
// 特殊键 source/type/subject 取事件字段，其余取 Attrs。
func (r *Rule) PartitionKey(ev *event.Event) string {
	if len(r.GroupBy) == 0 {
		return ""
	}
	parts := make([]string, len(r.GroupBy))
	for i, key := range r.GroupBy {
		switch key {
		case "source":
			parts[i] = ev.Source
		case "type":
			parts[i] = ev.Type
		case "subject":
			parts[i] = ev.Subject
		case "severity":
			parts[i] = string(ev.Severity)
		default:
			parts[i] = ev.Attrs[key]
		}
	}
	return strings.Join(parts, "\x00")
}

// MatchStep 判断事件是否可作为序列第 stepIdx 个条件。
func (r *Rule) MatchStep(ev *event.Event, stepIdx int) bool {
	if stepIdx < 0 || stepIdx >= len(r.Sequence) {
		return false
	}
	return r.Sequence[stepIdx].Match(ev)
}

type ruleError string

func (e ruleError) Error() string { return string(e) }
func errRule(format string, args ...any) error {
	return ruleError(fmt.Sprintf(format, args...))
}
