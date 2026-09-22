// Package datagen 在本地生成可复现的模拟安全事件原始日志流。
//
// 生成器故意混入：乱序时间偏移、重复记录、畸形记录，供引擎在测试与
// demo 中验证乱序一致、拒绝原因可区分与重复抑制等语义。
package datagen

import (
	"fmt"
	"math"
	"time"
)

// Generator 生成多种格式的原始日志记录。
type Generator struct {
	seed int64
}

// New 以随机种子构造生成器（相同种子 => 相同输出）。
func New(seed int64) *Generator { return &Generator{seed: seed} }

// RawRecord 是一条带"真实发生时间偏移"的原始记录。
type RawRecord struct {
	Raw      string
	Format   string
	OffsetMs int64 // 相对基准时间的发生偏移
}

func ts(baseUnixMs, offsetMs int64) string {
	return time.UnixMilli(baseUnixMs + offsetMs).UTC().Format(time.RFC3339)
}

// GenerateBruteForce 生成一次 SSH 暴力破解序列：
// 同一 src_ip 对 root 的多次认证失败后跟一次锁定；覆盖三种格式，
// 并混入乱序偏移、一条重复记录与干扰事件（其他用户）。
func (g *Generator) GenerateBruteForce(baseUnixMs int64) []RawRecord {
	ip := "10.0.0.9"
	var recs []RawRecord

	// 3 条 JSON 失败。
	for i := 0; i < 3; i++ {
		off := int64(i * 1000)
		recs = append(recs, RawRecord{
			Format:   "json",
			OffsetMs: off,
			Raw: fmt.Sprintf(
				`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":%q,"user":"root","action":"login_failed","host":"web-01"}`,
				ts(baseUnixMs, off), ip),
		})
	}
	// 2 条 keyvalue 失败。
	for i := 3; i < 5; i++ {
		off := int64(i * 1000)
		recs = append(recs, RawRecord{
			Format:   "keyvalue",
			OffsetMs: off,
			Raw: fmt.Sprintf(
				`timestamp=%q source=sshd event_type=auth.failure src_ip=%s user=root action=login_failed host=web-01`,
				ts(baseUnixMs, off), ip),
		})
	}
	// 1 条 syslog 失败 + 1 条锁定。
	offFail := int64(5000)
	recs = append(recs, RawRecord{
		Format:   "syslog",
		OffsetMs: offFail,
		Raw: fmt.Sprintf("%s web-01 sshd[901]: Failed password for root from %s port 51000",
			ts(baseUnixMs, offFail), ip),
	})
	offLock := int64(6000)
	recs = append(recs, RawRecord{
		Format:   "json",
		OffsetMs: offLock,
		Raw: fmt.Sprintf(
			`{"timestamp":%q,"source":"sshd","event_type":"auth.locked","src_ip":%q,"user":"root","action":"locked","host":"web-01"}`,
			ts(baseUnixMs, offLock), ip),
	})

	// 干扰：另一 IP 的失败，不应与上述序列聚合。
	recs = append(recs, RawRecord{
		Format:   "json",
		OffsetMs: 2500,
		Raw: fmt.Sprintf(
			`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":"10.0.0.77","user":"root","action":"login_failed","host":"web-01"}`,
			ts(baseUnixMs, 2500)),
	})
	// 干扰：同 IP 的其他用户失败（规则若按 user 分组则不命中）。
	recs = append(recs, RawRecord{
		Format:   "json",
		OffsetMs: 3500,
		Raw: fmt.Sprintf(
			`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":%q,"user":"alice","action":"login_failed","host":"web-01"}`,
			ts(baseUnixMs, 3500), ip),
	})

	// 重复投递：与第一条完全相同的记录（应在摄取层幂等去重）。
	recs = append(recs, recs[0])
	return recs
}

// GenerateMalformed 生成各类应被拒绝的畸形记录，每条的拒绝原因可区分：
// 空记录 / 无法识别格式 / JSON 结构错误 / 缺时间戳 / 坏时间戳 / 缺关键字段 / 未来时间。
func (g *Generator) GenerateMalformed(baseUnixMs int64) []RawRecord {
	// 相对基准时间未来 24 小时：在 1 小时 skew、固定时钟下被判为 future_event。
	future := time.UnixMilli(baseUnixMs).UTC().Add(24 * time.Hour).Format(time.RFC3339)
	return []RawRecord{
		{Format: "", OffsetMs: 0, Raw: ""},
		{Format: "", OffsetMs: 0, Raw: "   "},
		{Format: "", OffsetMs: 0, Raw: "this is not a log line at all"},
		{Format: "json", OffsetMs: 0, Raw: `{"timestamp":"` + ts(baseUnixMs, 0) + `", "source":`},
		{Format: "json", OffsetMs: 0, Raw: `{"source":"sshd","event_type":"auth.failure"}`},
		{Format: "json", OffsetMs: 0, Raw: `{"timestamp":"not-a-time","source":"sshd","event_type":"auth.failure"}`},
		{Format: "json", OffsetMs: 0, Raw: `{"timestamp":"` + ts(baseUnixMs, 0) + `","event_type":"auth.failure"}`},
		{Format: "json", OffsetMs: math.MaxInt64, Raw: `{"timestamp":"` + future + `","source":"sshd","event_type":"auth.failure"}`},
		{Format: "keyvalue", OffsetMs: 0, Raw: `timestamp="` + ts(baseUnixMs, 0) + `" foo=bar`},
	}
}

// Shuffle 使用与 correlate 包一致的确定性 LCG 做 Fisher-Yates 洗牌，
// 模拟乱序到达；同种子永远得到同一顺序。
func Shuffle(records []RawRecord, seed int64) []RawRecord {
	state := seed
	next := func() int {
		state = state*6364136223846793005 + 1442695040888963407
		return int(uint64(state) >> 33)
	}
	out := append([]RawRecord{}, records...)
	for i := len(out) - 1; i > 0; i-- {
		j := next() % (i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}
