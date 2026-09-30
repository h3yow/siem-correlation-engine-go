// Package snapshot 提供引擎运行状态的版本化快照导出、跨进程恢复与本地落盘能力。
//
// 快照语义：
//
//   - Export 只在极短的内存复制窗口内持有引擎/摄取的读锁；之后的 JSON
//     序列化与磁盘写入全部在锁外完成，不会卡住进行中的摄取，反复导出也
//     不会让内存占用增长（每次导出都是独立深拷贝）。
//   - 快照携带 format 身份标识与 version 版本号。读取时先做格式判定，
//     再按版本决定"直接读取 / 迁移 / 拒绝"：新版本引擎读旧快照走兼容读取，
//     旧引擎读新快照、或没有迁移路径的过旧快照，都返回带可区分错误码的
//     *snapshot.Error，绝不静默读入后算出错误结论。
package snapshot

import (
	"bytes"
	"encoding/json"
	"io"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
)

// Snapshot 是一份版本化的引擎运行状态快照。
type Snapshot struct {
	env envelopeDTO
}

// Version 返回快照格式版本。
func (s *Snapshot) Version() int { return s.env.Version }

// TakenAt 返回快照导出时刻。
func (s *Snapshot) TakenAt() time.Time { return s.env.TakenAt }

// ExportOption 调整导出行为。
type ExportOption func(*exportCfg)

type exportCfg struct {
	takenAt time.Time
}

// WithTakenAt 指定快照记录的导出时刻（默认为 time.Now()；测试可注入固定时钟）。
func WithTakenAt(t time.Time) ExportOption {
	return func(c *exportCfg) { c.takenAt = t }
}

// Export 采集摄取服务与关联引擎的当下状态，生成版本化快照。
//
// 慢序列化在调用方显式调用 Encode/WriteTo/SaveTo 时才发生，且不在
// 引擎/摄取锁内执行，因此不会卡住进行中的摄取。
func Export(svc *ingest.Service, eng *correlate.Engine, opts ...ExportOption) *Snapshot {
	cfg := exportCfg{takenAt: time.Now().UTC()}
	for _, o := range opts {
		o(&cfg)
	}

	engSt := eng.ExportState()
	ingSt := svc.ExportState()

	env := envelopeDTO{
		Format:  FormatMagic,
		Version: FormatVersion,
		TakenAt: cfg.takenAt.UTC(),
		Engine:  engineStateToDTO(engSt),
		Ingest: ingestStateToDTO(ingSt, ingestConfigDTO{
			MaxFutureSkew: duration(svc.MaxFutureSkew()),
			MinAge:        duration(svc.MinAge()),
		}),
	}
	return &Snapshot{env: env}
}

// Encode 将快照序列化为缩进的 JSON 字节（纯函数，可反复调用）。
func (s *Snapshot) Encode() ([]byte, error) {
	data, err := json.MarshalIndent(&s.env, "", "  ")
	if err != nil {
		return nil, snapErr(CodeCorrupt, s.env.Version, "marshal: %v", err)
	}
	return data, nil
}

// WriteTo 将快照编码后写入 w（实现 io.WriterTo）。
func (s *Snapshot) WriteTo(w io.Writer) (int64, error) {
	data, err := s.Encode()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// Decode 解析快照字节。
//
// 只做：格式身份判定（format 标识）、JSON 结构解析、版本范围判定；
// 不执行任何状态重建。成功后调用方应使用 Restore 做最终一致性校验与恢复。
func Decode(data []byte) (*Snapshot, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, snapErr(CodeCorrupt, 0, "empty snapshot data")
	}
	// 先单独探测 format 身份标识（对结构损坏不敏感），以区分
	// "不是快照" 与 "是快照但内容损坏"。
	var probe struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
	}
	_ = json.Unmarshal(data, &probe)
	if probe.Format != FormatMagic {
		return nil, snapErr(CodeNotSnapshot, probe.Version,
			"data is not an engine snapshot (format=%q)", probe.Format)
	}
	var env envelopeDTO
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, snapErr(CodeCorrupt, probe.Version, "cannot parse snapshot: %v", err)
	}
	if env.Format != FormatMagic {
		return nil, snapErr(CodeNotSnapshot, env.Version,
			"unexpected format %q, want %q", env.Format, FormatMagic)
	}
	if err := checkVersion(env.Version); err != nil {
		return nil, err
	}
	return &Snapshot{env: env}, nil
}

// checkVersion 判定快照版本是否可被当前引擎接受（或需要迁移）。
//
//   - version > 当前格式版本：来自更新引擎，明确拒绝（unsupported_version）；
//   - version < MinSupportedVersion：太旧且无迁移路径，拒绝（incompatible_version）；
//   - 其余：兼容读取（当前 v1 即自身）。
//
// 未来引入破坏性变更时，在此为旧版本注册 migrator 即可把旧快照升级为当前
// envelope，而不是默默按新语义解释旧字段。
func checkVersion(v int) error {
	switch {
	case v > FormatVersion:
		return snapErr(CodeUnsupportedVersion, v,
			"snapshot written by a newer engine; this engine supports up to v%d", FormatVersion)
	case v < MinSupportedVersion:
		return snapErr(CodeIncompatibleVersion, v,
			"snapshot too old and has no migration path; minimum supported is v%d", MinSupportedVersion)
	default:
		return nil
	}
}
