package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// timestampLayouts 覆盖本地模拟日志使用的全部时间戳布局。
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
	time.RFC1123,
	time.RFC822,
	"Jan 2 15:04:05", // 传统 syslog（无年份，补当前年）
}

// Normalizer 把字段映射归一为统一 Event，并执行完整性校验。
//
// 任何不完整/异常记录都通过 *event.RejectError 返回可区分原因，绝不静默丢弃。
//
// 时间判定口径（MaxFutureSkew/MinAge）属于运行配置：它会随引擎快照导出，
// 跨进程恢复后原样套用，不能被恢复方构造 Normalizer 时传入的取值覆盖。
// 字段受 mu 保护，允许"并发摄取"与"恢复套口径"安全共存。
type Normalizer struct {
	mu            sync.RWMutex
	MaxFutureSkew time.Duration
	MinAge        time.Duration
	nowFn         func() time.Time
}

// 默认时间口径：与 NewService(nil) 的历史默认保持一致。
const (
	// DefaultMaxFutureSkew 默认允许事件时间领先墙钟 1 小时。
	DefaultMaxFutureSkew = time.Hour
	// DefaultMinAge 默认不限制回溯年龄。
	DefaultMinAge time.Duration = 0
)

// TimePolicy 是摄取层事件时间判定口径的运行时形态。
type TimePolicy struct {
	MaxFutureSkew time.Duration
	MinAge        time.Duration
}

// NewNormalizer 构造归一化器。
func NewNormalizer(maxFutureSkew, minAge time.Duration) *Normalizer {
	return &Normalizer{
		MaxFutureSkew: maxFutureSkew,
		MinAge:        minAge,
		nowFn:         time.Now,
	}
}

// TimePolicy 返回当前生效的时间口径（并发安全）。
func (n *Normalizer) TimePolicy() TimePolicy {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return TimePolicy{MaxFutureSkew: n.MaxFutureSkew, MinAge: n.MinAge}
}

// ApplyTimePolicy 用快照导出那一刻的时间口径覆盖当前取值。
// 恢复路径必须调用它：即使恢复方构造 Normalizer 时传了别的（哪怕是默认）
// 值，也以快照为准，保证边界事件的 future/too_old 判定与原进程逐条一致。
func (n *Normalizer) ApplyTimePolicy(p TimePolicy) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.MaxFutureSkew = p.MaxFutureSkew
	n.MinAge = p.MinAge
}

// withClock 注入时钟（测试用）。
func (n *Normalizer) withClock(fn func() time.Time) *Normalizer {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nowFn = fn
	return n
}

// SetClock 注入时钟函数（测试/可复现演示用）。
func (n *Normalizer) SetClock(fn func() time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nowFn = fn
}

// reject 构造一个携带明确原因的错误。
func reject(reason event.Reason, detail string) error {
	return &event.RejectError{Record: event.RejectedRecord{Reason: reason, Detail: detail}}
}

// Normalize 将字段映射归一为事件；失败返回带明确 Reason 的 RejectError。
func (n *Normalizer) Normalize(format string, fields map[string]string, raw string) (event.Event, error) {
	if len(fields) == 0 {
		return event.Event{}, reject(event.ReasonMalformed, "no fields parsed")
	}

	// 1) 时间戳：缺失、无法解析、语义异常分别给出不同原因。
	tsRaw := firstNonEmpty(fields, "timestamp", "time", "@timestamp", "ts", "date")
	if tsRaw == "" {
		return event.Event{}, reject(event.ReasonMissingTimestamp,
			"record has none of timestamp/time/@timestamp/ts/date")
	}
	ts, ok := parseTimestamp(tsRaw)
	if !ok {
		return event.Event{}, reject(event.ReasonBadTimestamp,
			fmt.Sprintf("cannot parse timestamp %q", tsRaw))
	}
	n.mu.RLock()
	maxFutureSkew, minAge, nowFn := n.MaxFutureSkew, n.MinAge, n.nowFn
	n.mu.RUnlock()
	now := nowFn()
	if ts.After(now.Add(maxFutureSkew)) {
		return event.Event{}, reject(event.ReasonFutureEvent,
			fmt.Sprintf("event time %s is more than %s after now %s",
				ts.Format(time.RFC3339), maxFutureSkew, now.Format(time.RFC3339)))
	}
	if minAge > 0 && ts.Before(now.Add(-minAge)) {
		return event.Event{}, reject(event.ReasonTooOld,
			fmt.Sprintf("event time %s is older than max age %s",
				ts.Format(time.RFC3339), minAge))
	}

	// 2) 来源与事件类型：至少需要可识别来源。
	source := firstNonEmpty(fields, "source", "app", "service")
	if source == "" {
		return event.Event{}, reject(event.ReasonMissingEventTime, "missing source/app/service")
	}
	evType := firstNonEmpty(fields, "event_type", "eventtype", "type")
	if evType == "" {
		evType = inferEventType(fields)
	}
	if evType == "" {
		return event.Event{}, reject(event.ReasonMissingEventTime,
			"cannot infer event_type (no type/action/app-specific message)")
	}

	// 对 sshd 等散文式 syslog 消息做字段补全（不覆盖已显式给出的字段）。
	enrichFromMessage(fields)

	e := event.Event{
		ID:         deterministicEventID(format, raw),
		OccurredAt: ts.UTC(),
		Source:     source,
		EventType:  evType,
		SrcHost:    firstNonEmpty(fields, "src_host", "host"),
		DstHost:    firstNonEmpty(fields, "dst_host"),
		SrcIP:      firstNonEmpty(fields, "src_ip", "srcip", "client_ip", "src"),
		DstIP:      firstNonEmpty(fields, "dst_ip", "dstip", "dest_ip", "dst"),
		User:       firstNonEmpty(fields, "user", "username", "account"),
		Action:     firstNonEmpty(fields, "action", "result"),
		Status:     firstNonEmpty(fields, "status", "status_code"),
		Severity:   parseSeverity(firstNonEmpty(fields, "severity", "sev")),
		Attributes: map[string]string{},
		Raw:        raw,
		RawFormat:  format,
	}

	// 保留所有非标准字段供规则/排查使用。
	standard := map[string]bool{
		"timestamp": true, "time": true, "@timestamp": true, "ts": true, "date": true,
		"source": true, "app": true, "service": true,
		"event_type": true, "eventtype": true, "type": true,
		"src_host": true, "host": true, "dst_host": true,
		"src_ip": true, "srcip": true, "client_ip": true, "src": true,
		"dst_ip": true, "dstip": true, "dest_ip": true, "dst": true,
		"user": true, "username": true, "account": true,
		"action": true, "result": true, "status": true, "status_code": true,
		"severity": true, "sev": true, "message": true, "pid": true,
	}
	for k, v := range fields {
		if !standard[k] {
			e.Attributes[k] = v
		} else if k == "message" {
			e.Attributes["message"] = v
		}
	}
	return e, nil
}

// deterministicEventID 基于格式与原始内容计算稳定的事件 ID。
//
// 使用内容哈希而非自增序号，保证同一条记录在任意并发调度/重放轮次中
// 得到相同 ID —— 这是"乱序、并发下告警结论一致"的全序键基础。
func deterministicEventID(format, raw string) string {
	h := sha256.Sum256([]byte(format + "\x00" + trimSpace(raw)))
	return "evt-" + hex.EncodeToString(h[:8])
}

var sshdPatterns = []struct {
	eventType string
	action    string
}{
	{"auth.failure", "login_failed"},
	{"auth.success", "login_success"},
	{"auth.locked", "locked"},
}

// enrichFromMessage 从散文式消息中抽取 user / ip 等字段（只补全缺失字段）。
func enrichFromMessage(fields map[string]string) {
	msg := fields["message"]
	if msg == "" {
		return
	}
	app := strings.ToLower(firstNonEmpty(fields, "app", "source"))

	// 统一补 action：inferEventType 已经给出 event_type，这里同步给出 action。
	if firstNonEmpty(fields, "action", "result") == "" {
		for _, p := range sshdPatterns {
			// 与 inferEventType 的消息特征保持一致。
			switch {
			case p.eventType == "auth.failure" &&
				(strings.Contains(msg, "Failed password") || strings.Contains(msg, "authentication failure")):
				fields["action"] = p.action
			case p.eventType == "auth.success" &&
				(strings.Contains(msg, "Accepted password") || strings.Contains(msg, "session opened")):
				fields["action"] = p.action
			case p.eventType == "auth.locked" &&
				(strings.Contains(msg, "account locked") || strings.Contains(msg, "lockout")):
				fields["action"] = p.action
			}
		}
	}

	if app != "sshd" {
		return
	}
	if firstNonEmpty(fields, "user", "username", "account") == "" {
		if m := sshdUserRe.FindStringSubmatch(msg); m != nil {
			fields["user"] = m[1]
		}
	}
	if firstNonEmpty(fields, "src_ip", "srcip", "client_ip", "src") == "" {
		if m := sshdIPRe.FindStringSubmatch(msg); m != nil {
			fields["src_ip"] = m[1]
		}
	}
}

var (
	sshdUserRe = regexp.MustCompile(`(?:for(?: invalid user)?|user=)\s+([A-Za-z0-9_.@-]+)`)
	sshdIPRe   = regexp.MustCompile(`from\s+(\d{1,3}(?:\.\d{1,3}){3})`)
)

// firstNonEmpty 返回 fields 中第一个存在且非空的键值。
func firstNonEmpty(fields map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(fields[k]); v != "" {
			return v
		}
	}
	return ""
}

// parseTimestamp 尝试多种常见时间戳布局；Unix 秒/毫秒纯数字也支持。
func parseTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// Unix epoch：秒（10 位）或毫秒（13 位）。
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		switch len(s) {
		case 10:
			return time.Unix(n, 0).UTC(), true
		case 13:
			return time.UnixMilli(n).UTC(), true
		}
	}
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			if layout == "Jan 2 15:04:05" {
				t = time.Date(time.Now().Year(), t.Month(), t.Day(),
					t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
			}
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// parseSeverity 解析严重级别文本。
func parseSeverity(s string) event.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "emerg", "emergency", "fatal":
		return event.SeverityCritical
	case "high":
		return event.SeverityHigh
	case "medium", "med", "warning", "warn":
		return event.SeverityMedium
	case "low":
		return event.SeverityLow
	case "info", "informational", "notice":
		return event.SeverityInfo
	default:
		return event.SeverityUnknown
	}
}

// inferEventType 从 action / app / message 推断归一化事件类型。
//
// 约定的归一化类型：
//   - auth.failure / auth.success：认证失败/成功
//   - auth.locked：账号锁定
//   - net.connection / net.deny：网络连接/拒绝
//   - host.alert：通用主机告警
func inferEventType(fields map[string]string) string {
	action := strings.ToLower(firstNonEmpty(fields, "action", "result"))
	app := strings.ToLower(firstNonEmpty(fields, "app"))
	msg := strings.ToLower(firstNonEmpty(fields, "message"))

	switch action {
	case "login_failed", "login_fail", "auth_failure", "failed_login", "fail", "denied", "failure":
		return "auth.failure"
	case "login_success", "success", "accepted", "ok":
		return "auth.success"
	case "locked", "lockout":
		return "auth.locked"
	case "allow", "allowed":
		return "net.connection"
	case "block", "blocked", "deny":
		return "net.deny"
	}

	switch {
	case strings.Contains(msg, "failed password") || strings.Contains(msg, "authentication failure"):
		return "auth.failure"
	case strings.Contains(msg, "accepted password") || strings.Contains(msg, "session opened"):
		return "auth.success"
	case strings.Contains(msg, "account locked") || strings.Contains(msg, "lockout"):
		return "auth.locked"
	}

	switch app {
	case "sshd", "login":
		return "" // 没有足够线索时拒绝，而不是猜测
	case "nginx", "apache", "web":
		return "web.request"
	case "firewall", "iptables":
		return "net.connection"
	}
	return ""
}
