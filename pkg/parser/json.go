package parser

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// JSONParser 解析 JSON 日志行。
// 期望字段：id, ts(RFC3339 字符串或 unix 秒), type, severity, subject, message, attrs。
type JSONParser struct{}

func NewJSONParser() *JSONParser   { return &JSONParser{} }
func (p *JSONParser) Name() string { return "json" }

type jsonRecord struct {
	ID       string            `json:"id"`
	TS       json.RawMessage   `json:"ts"`
	Type     string            `json:"type"`
	Severity string            `json:"severity"`
	Subject  string            `json:"subject"`
	Message  string            `json:"message"`
	Attrs    map[string]string `json:"attrs"`
}

func (p *JSONParser) Parse(line, source string) (*event.Event, error) {
	var rec jsonRecord
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		return nil, Errf(event.RejectMalformed, "invalid json: %v", err)
	}
	if rec.ID == "" {
		return nil, Errf(event.RejectMissingID, "json record missing id")
	}
	if rec.Type == "" {
		return nil, Errf(event.RejectMissingType, "json record missing type")
	}
	if len(rec.TS) == 0 || string(rec.TS) == "null" {
		return nil, Errf(event.RejectMissingTime, "json record missing ts")
	}
	ts, err := parseTimestamp(rec.TS)
	if err != nil {
		return nil, err
	}
	return &event.Event{
		ID:        rec.ID,
		Source:    source,
		Type:      rec.Type,
		Timestamp: ts,
		Severity:  NormalizeSeverity(rec.Severity),
		Subject:   rec.Subject,
		Message:   rec.Message,
		Raw:       line,
		Attrs:     rec.Attrs,
	}, nil
}

// parseTimestamp 支持 RFC3339 字符串与 unix 秒（整数或浮点）。
func parseTimestamp(raw json.RawMessage) (time.Time, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return time.Time{}, Errf(event.RejectBadTimestamp, "empty timestamp string")
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC(), nil
		}
		if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
			return t.UTC(), nil
		}
		return time.Time{}, Errf(event.RejectBadTimestamp, "unparseable timestamp %q", s)
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return time.Time{}, Errf(event.RejectBadTimestamp, "timestamp must be RFC3339 string or unix seconds")
	}
	sec := int64(f)
	if sec <= 0 || sec > 1<<40 {
		return time.Time{}, Errf(event.RejectBadTimestamp, "unix timestamp %v out of plausible range", f)
	}
	return time.Unix(sec, 0).UTC(), nil
}

// NormalizeSeverity 归一化严重级别字符串；未知值归一为 unknown。
func NormalizeSeverity(s string) event.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "information", "notice", "debug":
		return event.SeverityInfo
	case "low":
		return event.SeverityLow
	case "medium", "med", "warn", "warning":
		return event.SeverityMedium
	case "high", "error", "err":
		return event.SeverityHigh
	case "critical", "crit", "fatal", "alert", "emerg":
		return event.SeverityCritical
	default:
		return event.SeverityUnknown
	}
}
