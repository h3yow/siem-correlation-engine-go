// Package event 定义归一化后的统一安全事件模型。
package event

import "time"

// Severity 表示事件严重级别。
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = [...]string{
	"unknown", "info", "low", "medium", "high", "critical",
}

func (s Severity) String() string {
	if int(s) < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// Event 是所有本地日志格式归一化后的统一事件模型。
//
// 字段语义：
//   - ID: 事件全局唯一标识（由摄取层保证，幂等键）。
//   - OccurredAt: 事件实际发生时间（来自日志记录），所有时间窗判定均以此为准。
//   - Source: 事件来源（如 sshd / web_access / firewall / endpoint）。
//   - EventType: 归一化事件类型（如 auth.failure、auth.success、net.connection）。
//   - SrcHost / DstHost: 源主机与目标主机。
//   - SrcIP / DstIP: 源 IP 与目标 IP。
//   - User: 关联用户（可空）。
//   - Action: 动作（deny/allow/login_failed/login_success 等）。
//   - Status: 状态码或结果字符串（可空）。
//   - Raw: 原始日志记录内容，保证可追溯。
//   - RawFormat: 原始格式标识（json/syslog/keyvalue）。
type Event struct {
	ID         string
	OccurredAt time.Time
	Source     string
	EventType  string
	SrcHost    string
	DstHost    string
	SrcIP      string
	DstIP      string
	User       string
	Action     string
	Status     string
	Severity   Severity
	Attributes map[string]string
	Raw        string
	RawFormat  string
}

// EventTime 实现有序接口所需的事件时间。
func (e Event) EventTime() time.Time { return e.OccurredAt }

// Clone 返回事件的深拷贝，避免外部修改内部 map。
func (e Event) Clone() Event {
	cp := e
	if e.Attributes != nil {
		cp.Attributes = make(map[string]string, len(e.Attributes))
		for k, v := range e.Attributes {
			cp.Attributes[k] = v
		}
	}
	return cp
}
