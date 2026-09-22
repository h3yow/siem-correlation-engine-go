package event

// Reason 是记录被拒绝的可区分原因枚举。
//
// 任何无法归一化的记录都必须携带明确的 Reason 返回，绝不允许静默丢弃。
type Reason string

const (
	ReasonEmpty             Reason = "empty_record"        // 空记录
	ReasonUnsupportedFormat Reason = "unsupported_format"  // 无法识别的格式
	ReasonMalformed         Reason = "malformed"           // 结构性解析失败（如非法 JSON）
	ReasonMissingTimestamp  Reason = "missing_timestamp"   // 缺失时间戳字段
	ReasonBadTimestamp      Reason = "bad_timestamp"       // 时间戳无法解析或语义异常
	ReasonMissingEventTime  Reason = "missing_event_field" // 缺少判定必需的事件字段
	ReasonFutureEvent       Reason = "future_event"        // 事件时间远晚于摄取墙钟时间
	ReasonTooOld            Reason = "too_old"             // 事件时间早于允许的最早边界
	ReasonDuplicate         Reason = "duplicate"           // 幂等去重：同一事件重复摄取
)

// RejectedRecord 描述一条被拒绝摄取的原始记录及其可区分原因。
type RejectedRecord struct {
	Raw      string
	Format   string
	Reason   Reason
	Detail   string
	SeenAtNs int64 // 摄取层墙钟纳秒，便于排查乱序
}

// RejectError 使拒绝原因可作为 error 传播。
type RejectError struct {
	Record RejectedRecord
}

func (e *RejectError) Error() string {
	r := e.Record
	if r.Detail != "" {
		return string(r.Reason) + ": " + r.Detail
	}
	return string(r.Reason)
}
