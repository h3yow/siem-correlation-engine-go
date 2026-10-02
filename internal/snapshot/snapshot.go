// Package snapshot 定义引擎运行状态快照的磁盘格式、版本协商与编解码。
//
// 快照用于把常驻服务的关联引擎在某一时刻的全部运行状态导出为本地文件，
// 并在新进程中无损恢复：恢复后继续处理事件流（乱序/迟到/并发/重复投递），
// 告警结论与"进程从未重启"完全一致——不重、不漏、身份与依据可对上。
//
// 版本演进策略（不能默默读入旧快照算出错结论）：
//   - 每份快照带 FormatVersion 与 EngineID；当前写出格式为 CurrentFormatVersion。
//   - 新版本读取旧版本：[MinSupportedVersion, CurrentFormatVersion] 区间内的
//     版本直接兼容解码；区间外（典型：未来版本）返回 *VersionError，
//     且 errors.Is(err, ErrUnsupportedVersion) 为真，拒绝原因可与其他失败区分；
//   - 载荷被篡改/截断导致校验和不匹配返回 ErrChecksumMismatch；
//     文件无法解析返回 ErrMalformedSnapshot。
package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CurrentFormatVersion 是当前进程写出的快照格式版本。
const CurrentFormatVersion = 1

// MinSupportedVersion 是本进程能够兼容读取的最低快照格式版本。
const MinSupportedVersion = 1

// Envelope 是快照文件的最外层容器：版本/元信息与状态载荷分离，
// 便于在不触碰业务状态的前提下先做版本协商与完整性校验。
type Envelope struct {
	FormatVersion int    `json:"format_version"`
	EngineID      string `json:"engine_id"`
	// CreatedAt 是快照导出完成的墙钟时间（RFC3339Nano，UTC）。
	CreatedAt string `json:"created_at"`
	// Checksum 是 Canonical(state) 的 sha256（十六进制），用于检测截断/篡改。
	Checksum string `json:"checksum"`
	State    State  `json:"state"`
}

// State 是需要跨进程恢复的全部引擎运行状态。
type State struct {
	EngineID        string          `json:"engine_id"`
	AllowedLateness DurationJSON    `json:"allowed_lateness"`
	Watermark       time.Time       `json:"watermark"`
	RuleOrder       []string        `json:"rule_order"`
	Rules           []RuleState     `json:"rules"`
	Pending         []EventState    `json:"pending"`
	Suppression     SuppressorState `json:"suppression"`
	// IngestSeen 是摄取层幂等去重表 dedupKey -> eventID；
	// 仅在引擎绑定了摄取服务时导出，保证重复投递跨重启仍返回 duplicate。
	IngestSeen     map[string]string `json:"ingest_seen,omitempty"`
	IngestDupCount int               `json:"ingest_dup_count"`
	// TimePolicy 是导出那一刻摄取层事件时间判定口径（未来容忍/最早可回溯）。
	// 它必须随快照延续：恢复后边界附近（刚好容忍/刚好超出/最早边界两侧）
	// 的 future_event / too_old 判定要与原进程逐条一致，不能退回默认值。
	// 指针+omitempty 用于区分"显式导出的口径（含零值）"与"旧快照缺失该节"。
	TimePolicy *TimePolicyState `json:"time_policy,omitempty"`
}

// TimePolicyState 是事件时间判定口径的持久化形态（纳秒整数）。
type TimePolicyState struct {
	// MaxFutureSkew 允许事件时间领先墙钟多久；ts > now+MaxFutureSkew 即 future_event。
	MaxFutureSkew DurationJSON `json:"max_future_skew"`
	// MinAge 允许回溯的最早年龄；ts < now-MinAge（MinAge>0 时）即 too_old。0 表示不限制。
	MinAge DurationJSON `json:"min_age"`
}

// DurationJSON 把 time.Duration 以纳秒整数持久化（比字符串更不易在
// 版本演进中产生解析歧义）。
type DurationJSON int64

// RuleState 是单条规则检测器的可恢复状态。
type RuleState struct {
	ID      string       `json:"id"`
	Version int          `json:"version"`
	Rule    RuleDef      `json:"rule"`
	Fired   []string     `json:"fired"`
	Groups  []GroupState `json:"groups"`
}

// RuleDef 是规则内容的持久化形态（与 rule.Rule 对应，时长以纳秒表示）。
type RuleDef struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Pattern     []MatchDef   `json:"pattern"`
	Window      DurationJSON `json:"window"`
	MaxGap      DurationJSON `json:"max_gap"`
	GroupBy     string       `json:"group_by"`
}

// MatchDef 是 Pattern 单个位置的持久化形态。
type MatchDef struct {
	Source    string `json:"source,omitempty"`
	EventType string `json:"event_type,omitempty"`
	Action    string `json:"action,omitempty"`
	User      string `json:"user,omitempty"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
}

// GroupState 是某条规则在某个分组键内保留的窗口事件。
// 部分匹配链（partials）不持久化：它们是窗内事件的确定性派生物，
// 恢复后由后续事件触发的全量 DP 重枚举重新得出（语义零损失）。
type GroupState struct {
	Key    string       `json:"key"`
	Events []EventState `json:"events"`
}

// EventState 是归一化事件的持久化形态。
type EventState struct {
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
	Severity   string            `json:"severity"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Raw        string            `json:"raw"`
	RawFormat  string            `json:"raw_format"`
}

// SuppressorState 是抑制器全部活动桶的可恢复状态。
type SuppressorState struct {
	// AggregateBy 是聚合维度配置（如 [rule_id, src_ip]），决定桶身份；
	// 必须随快照保存，否则恢复后退回默认维度会改变抑制结论。
	AggregateBy    []string      `json:"aggregate_by"`
	QuietFor       DurationJSON  `json:"quiet_for"`
	MaxOccurrences int           `json:"max_occurrences"`
	Buckets        []BucketState `json:"buckets"`
}

// BucketState 是单个聚合抑制桶的可恢复状态。
type BucketState struct {
	AggregateKey   string    `json:"aggregate_key"`
	OpenedAt       time.Time `json:"opened_at"`
	QuietUntil     time.Time `json:"quiet_until"`
	FirstAlertKey  string    `json:"first_alert_key"`
	OccurrenceCnt  int       `json:"occurrence_cnt"`
	SampleEventIDs []string  `json:"sample_event_ids,omitempty"`
}

// 可区分的快照失败原因。调用方可用 errors.Is 精确判断。
var (
	// ErrMalformedSnapshot 文件不是合法快照（无法解析为 Envelope）。
	ErrMalformedSnapshot = errors.New("snapshot: malformed snapshot file")
	// ErrUnsupportedVersion 快照格式版本不在本进程支持区间内。
	ErrUnsupportedVersion = errors.New("snapshot: unsupported format version")
	// ErrChecksumMismatch 状态载荷校验和不匹配（截断/损坏/被篡改）。
	ErrChecksumMismatch = errors.New("snapshot: state checksum mismatch")
	// ErrMissingTimePolicy 快照缺少事件时间判定口径节（典型：旧版本写出的快照）。
	// 不能默默拿默认值顶上，否则恢复后边界事件会被误放/误拒。
	ErrMissingTimePolicy = errors.New("snapshot: missing event time policy")
	// ErrInvalidTimePolicy 快照带了时间口径但取值不合理（如负数时长）。
	ErrInvalidTimePolicy = errors.New("snapshot: invalid event time policy")
)

// VersionError 携带版本协商细节，便于给出明确且可区分的拒绝/迁移原因；
// errors.Is(err, ErrUnsupportedVersion) 为真。
type VersionError struct {
	Got      int
	Min, Max int
}

func (e *VersionError) Error() string {
	return fmt.Sprintf("%s: snapshot format_version=%d, this build supports [%d,%d]",
		ErrUnsupportedVersion, e.Got, e.Min, e.Max)
}

// Unwrap 使 errors.Is(err, ErrUnsupportedVersion) 成立。
func (e *VersionError) Unwrap() error { return ErrUnsupportedVersion }

// Canonical 返回状态的规范 JSON 字节：Go 的 encoding/json 对 struct 按
// 字段声明顺序、对 map 按键排序输出，因此同一状态在任何进程中字节一致，
// 可直接用于校验和与跨版本比对。
func Canonical(st State) ([]byte, error) {
	return json.Marshal(st)
}

func checksum(st State) (string, error) {
	b, err := Canonical(st)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Encode 在内存中把 State 编码为带版本与校验和的快照字节（尚未落盘）。
func Encode(st State, engineID string) ([]byte, error) {
	sum, err := checksum(st)
	if err != nil {
		return nil, fmt.Errorf("snapshot: compute checksum: %w", err)
	}
	env := Envelope{
		FormatVersion: CurrentFormatVersion,
		EngineID:      engineID,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Checksum:      sum,
		State:         st,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&env); err != nil {
		return nil, fmt.Errorf("snapshot: encode envelope: %w", err)
	}
	return buf.Bytes(), nil
}

// Decode 解析快照字节：先做格式校验、版本协商与校验和核验，再返回 State。
//
// 顺序刻意设计为：格式 -> 版本 -> 校验和，任何一步失败都返回互不混淆的
// 可区分错误，绝不"默默读进来"。
func Decode(data []byte) (State, error) {
	var env Envelope
	if err := json.Unmarshal(bytes.TrimSpace(data), &env); err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrMalformedSnapshot, err)
	}
	if env.FormatVersion < MinSupportedVersion || env.FormatVersion > CurrentFormatVersion {
		return State{}, &VersionError{
			Got: env.FormatVersion, Min: MinSupportedVersion, Max: CurrentFormatVersion,
		}
	}
	sum, err := checksum(env.State)
	if err != nil {
		return State{}, fmt.Errorf("%w: %v", ErrChecksumMismatch, err)
	}
	if sum != env.Checksum {
		return State{}, fmt.Errorf("%w: want %s got %s",
			ErrChecksumMismatch, env.Checksum, sum)
	}
	if err := ValidateTimePolicy(env.State.TimePolicy); err != nil {
		return State{}, err
	}
	return env.State, nil
}

// ValidateTimePolicy 校验快照里的事件时间判定口径：节必须存在（缺失说明
// 快照由不导出口径的旧版本写出），且两个时长取值必须合理。该失败与
// "文件损坏(ErrChecksumMismatch)""版本不兼容(ErrUnsupportedVersion)"
// 互相可区分，调用方可用 errors.Is 精确判断。
func ValidateTimePolicy(tp *TimePolicyState) error {
	if tp == nil {
		return fmt.Errorf("%w: snapshot predates time policy persistence; "+
			"refusing to substitute defaults (accept/reject results would diverge)",
			ErrMissingTimePolicy)
	}
	if tp.MaxFutureSkew < 0 {
		return fmt.Errorf("%w: max_future_skew must not be negative, got %d",
			ErrInvalidTimePolicy, tp.MaxFutureSkew)
	}
	if tp.MinAge < 0 {
		return fmt.Errorf("%w: min_age must not be negative, got %d",
			ErrInvalidTimePolicy, tp.MinAge)
	}
	return nil
}
