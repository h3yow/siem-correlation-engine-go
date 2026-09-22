package alert

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// Alert 是一次关联命中产生的告警。
type Alert struct {
	ID          string            `json:"id"`
	Fingerprint string            `json:"fingerprint"`
	RuleID      string            `json:"rule_id"`
	RuleVersion int               `json:"rule_version"`
	Partition   string            `json:"partition"`
	Severity    event.Severity    `json:"severity"`
	EventIDs    []string          `json:"event_ids"`
	WindowStart time.Time         `json:"window_start"`
	WindowEnd   time.Time         `json:"window_end"`
	FiredAt     time.Time         `json:"fired_at"`
	Reason      string            `json:"reason"`
	Suppressed  bool              `json:"suppressed"`
	Count       int               `json:"count"`
	Attrs       map[string]string `json:"attrs,omitempty"`
}

// FingerprintFor 基于 规则+分区+证据事件集合（排序后）计算稳定指纹。
// 与事件到达顺序无关：乱序/并发下同一事件序列必得同一指纹。
func FingerprintFor(ruleID, partition string, evs []*event.Event) string {
	ids := make([]string, len(evs))
	for i, ev := range evs {
		ids[i] = ev.ID
	}
	sort.Strings(ids)
	h := sha1.New()
	h.Write([]byte(ruleID))
	h.Write([]byte{0})
	h.Write([]byte(partition))
	h.Write([]byte{0})
	h.Write([]byte(strings.Join(ids, ",")))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:10])
}

// HighestSeverity 返回证据链中的最高级别。
func HighestSeverity(evs []*event.Event) event.Severity {
	rank := map[event.Severity]int{
		event.SeverityUnknown:  0,
		event.SeverityInfo:     1,
		event.SeverityLow:      2,
		event.SeverityMedium:   3,
		event.SeverityHigh:     4,
		event.SeverityCritical: 5,
	}
	best := event.SeverityUnknown
	for _, ev := range evs {
		if rank[ev.Severity] > rank[best] {
			best = ev.Severity
		}
	}
	return best
}
