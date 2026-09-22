// Package alert 定义关联检测产出的告警模型。
package alert

import (
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// Kind 标识一条产出是新告警还是被抑制的聚合命中。
type Kind string

const (
	KindFired      Kind = "fired"      // 实际发出的新告警
	KindSuppressed Kind = "suppressed" // 被抑制：归入某活动告警的聚合桶
)

// Evidence 记录告警判定依据中的单个事件证据。
type Evidence struct {
	EventID    string
	OccurredAt time.Time
	Source     string
	EventType  string
	MatchIdx   int // 命中规则 Pattern 的下标
	Role       string
}

// Alert 是规则命中后产生的、可解释的告警结论。
//
// 可解释性字段：
//   - DedupKey: 告警身份键。同一序列在任何重放/并发/规则变更下都只产生一个 Fired。
//   - RuleVersion: 产生该告警时规则内容的版本号。
//   - Evidence: 命中序列中的全部事件，按 OccurredAt 排序。
//   - FirstEventAt / LastEventAt: 序列时间范围。
//   - Reason: 人类可读的判定依据说明。
type Alert struct {
	ID            string
	DedupKey      string
	RuleID        string
	RuleVersion   int
	RuleName      string
	Severity      event.Severity
	Kind          Kind
	FirstEventAt  time.Time
	LastEventAt   time.Time
	FiredAt       time.Time
	Evidence      []Evidence
	Reason        string
	AggregateKey  string // 抑制聚合维度
	SuppressedBy  string // 若被抑制，指向活动告警的 DedupKey
	OccurrenceCnt int    // 该聚合桶内累计命中次数（含本次）
}

// EventIDs 返回证据中的事件 ID 列表（按证据顺序）。
func (a Alert) EventIDs() []string {
	ids := make([]string, len(a.Evidence))
	for i, ev := range a.Evidence {
		ids[i] = ev.EventID
	}
	return ids
}

// FiredAlert 从命中结果构造一条 Fired 告警。
func FiredAlert(ruleID string, ruleVersion int, ruleName string, sev event.Severity, ev []Evidence, dedupKey, reason string, at time.Time) Alert {
	cp := make([]Evidence, len(ev))
	copy(cp, ev)
	a := Alert{
		DedupKey:      dedupKey,
		RuleID:        ruleID,
		RuleVersion:   ruleVersion,
		RuleName:      ruleName,
		Severity:      sev,
		Kind:          KindFired,
		Evidence:      cp,
		Reason:        reason,
		OccurrenceCnt: 1,
		FiredAt:       at,
	}
	if len(cp) > 0 {
		a.ID = ruleID + ":" + dedupKey
		a.FirstEventAt = cp[0].OccurredAt
		a.LastEventAt = cp[len(cp)-1].OccurredAt
	}
	return a
}
