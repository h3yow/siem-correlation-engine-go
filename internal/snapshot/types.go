package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// FormatMagic 是快照文件的固定身份标识，用于与任意其他 JSON 区分。
const FormatMagic = "siem-engine-snapshot"

// FormatVersion 是当前快照格式版本。
const FormatVersion = 1

// MinSupportedVersion 是当前引擎能够读取的最旧快照版本。
// 更旧的快照会被明确拒绝（需要迁移），绝不静默读取后算出错误结论。
const MinSupportedVersion = 1

// ErrorCode 是快照读取/恢复失败的可区分原因。
type ErrorCode string

const (
	// CodeNotSnapshot 数据不是本引擎快照（缺少/不匹配 format 标识）。
	CodeNotSnapshot ErrorCode = "not_a_snapshot"
	// CodeCorrupt 快照字节无法解析或结构损坏。
	CodeCorrupt ErrorCode = "corrupt"
	// CodeUnsupportedVersion 快照来自更新版本的引擎，当前版本无法读取。
	CodeUnsupportedVersion ErrorCode = "unsupported_version"
	// CodeIncompatibleVersion 快照版本过旧或缺少可用迁移路径，需要显式迁移。
	CodeIncompatibleVersion ErrorCode = "incompatible_version"
	// CodeInvalid 快照可解析但内容未通过一致性校验。
	CodeInvalid ErrorCode = "invalid"
)

// Error 携带可区分的快照失败原因，调用方可用 errors.As 精确判定。
type Error struct {
	Code    ErrorCode
	Version int
	Msg     string
}

func (e *Error) Error() string {
	if e.Version != 0 {
		return fmt.Sprintf("snapshot: %s (version=%d): %s", e.Code, e.Version, e.Msg)
	}
	return fmt.Sprintf("snapshot: %s: %s", e.Code, e.Msg)
}

func snapErr(code ErrorCode, version int, format string, args ...any) *Error {
	return &Error{Code: code, Version: version, Msg: fmt.Sprintf(format, args...)}
}

// CodeOf 从错误中提取快照错误码；非快照错误返回空串。
func CodeOf(err error) ErrorCode {
	var se *Error
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

// duration 是快照中的时间长度类型：JSON 中存纳秒整数，同时兼容
// "10s" 这样的时长字符串，便于人工阅读与未来演进。
type duration time.Duration

func (d duration) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(time.Duration(d).Nanoseconds(), 10)), nil
}

func (d *duration) UnmarshalJSON(data []byte) error {
	var ns int64
	if err := json.Unmarshal(data, &ns); err == nil {
		*d = duration(time.Duration(ns))
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = duration(parsed)
	return nil
}

func (d duration) std() time.Duration { return time.Duration(d) }

// ---- 快照 JSON DTO（字段标签带 snake_case，长期演进时只增不减/不改语义） ----

type envelopeDTO struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	TakenAt time.Time `json:"taken_at"`
	Engine  engineDTO `json:"engine"`
	Ingest  ingestDTO `json:"ingest"`
}

type matchDTO struct {
	Source    string `json:"source"`
	EventType string `json:"event_type"`
	Action    string `json:"action"`
	User      string `json:"user"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
}

type ruleDTO struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Severity    int        `json:"severity"`
	Pattern     []matchDTO `json:"pattern"`
	Window      duration   `json:"window_ns"`
	MaxGap      duration   `json:"max_gap_ns"`
	GroupBy     string     `json:"group_by"`
}

type eventDTO struct {
	ID         string            `json:"id"`
	OccurredAt time.Time         `json:"occurred_at"`
	Source     string            `json:"source"`
	EventType  string            `json:"event_type"`
	SrcHost    string            `json:"src_host"`
	DstHost    string            `json:"dst_host"`
	SrcIP      string            `json:"src_ip"`
	DstIP      string            `json:"dst_ip"`
	User       string            `json:"user"`
	Action     string            `json:"action"`
	Status     string            `json:"status"`
	Severity   int               `json:"severity"`
	Attributes map[string]string `json:"attributes"`
	Raw        string            `json:"raw"`
	RawFormat  string            `json:"raw_format"`
}

type windowGroupDTO struct {
	Key    string      `json:"key"`
	Events []*eventDTO `json:"events"`
}

type detectorDTO struct {
	Rule    ruleDTO          `json:"rule"`
	Version int              `json:"version"`
	Fired   []string         `json:"fired"`
	Groups  []windowGroupDTO `json:"groups"`
}

type suppressionCfgDTO struct {
	AggregateBy    []string `json:"aggregate_by"`
	QuietFor       duration `json:"quiet_for_ns"`
	MaxOccurrences int      `json:"max_occurrences"`
}

type bucketDTO struct {
	AggregateKey   string    `json:"aggregate_key"`
	OpenedAt       time.Time `json:"opened_at"`
	QuietUntil     time.Time `json:"quiet_until"`
	FirstAlertKey  string    `json:"first_alert_key"`
	OccurrenceCnt  int       `json:"occurrence_cnt"`
	SampleEventIDs []string  `json:"sample_event_ids"`
}

type engineDTO struct {
	Watermark       time.Time         `json:"watermark"`
	AllowedLateness duration          `json:"allowed_lateness_ns"`
	Suppression     suppressionCfgDTO `json:"suppression"`
	Buckets         []bucketDTO       `json:"suppress_buckets"`
	RuleOrder       []string          `json:"rule_order"`
	Rules           []detectorDTO     `json:"rules"`
	Pending         []*eventDTO       `json:"pending"`
}

type ingestConfigDTO struct {
	MaxFutureSkew duration `json:"max_future_skew_ns"`
	MinAge        duration `json:"min_age_ns"`
}

type ingestDTO struct {
	Config   ingestConfigDTO   `json:"config"`
	Seen     map[string]string `json:"seen"`
	DupCount int               `json:"dup_count"`
}
