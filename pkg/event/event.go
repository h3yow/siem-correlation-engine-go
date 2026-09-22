package event

import "time"

// Severity 是归一化后的事件严重级别。
type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Event 是所有日志源归一化后的统一事件模型。
type Event struct {
	ID        string            `json:"id"`
	Source    string            `json:"source"`
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	Severity  Severity          `json:"severity"`
	Subject   string            `json:"subject"`
	Message   string            `json:"message"`
	Raw       string            `json:"raw"`
	Attrs     map[string]string `json:"attrs"`
	IngestSeq int64             `json:"ingest_seq"`
}

// RejectReason 用于区分记录被拒绝的原因。
type RejectReason string

const (
	RejectEmpty          RejectReason = "empty_record"
	RejectUnsupportedFmt RejectReason = "unsupported_format"
	RejectMalformed      RejectReason = "malformed_record"
	RejectMissingID      RejectReason = "missing_id"
	RejectMissingType    RejectReason = "missing_type"
	RejectMissingTime    RejectReason = "missing_timestamp"
	RejectBadTimestamp   RejectReason = "bad_timestamp"
	RejectFutureTime     RejectReason = "future_timestamp"
	RejectTooOld         RejectReason = "timestamp_too_old"
	RejectDuplicateID    RejectReason = "duplicate_event_id"
	RejectLateDropped    RejectReason = "late_beyond_watermark"
)

// RejectedRecord 记录被拒绝的原始记录及可区分原因。
type RejectedRecord struct {
	Raw    string       `json:"raw"`
	Source string       `json:"source"`
	Reason RejectReason `json:"reason"`
	Detail string       `json:"detail"`
}

func (r RejectedRecord) Error() string { return string(r.Reason) + ": " + r.Detail }

// Clock 返回当前时间，便于测试注入。
type Clock func() time.Time
