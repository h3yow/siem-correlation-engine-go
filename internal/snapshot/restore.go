package snapshot

import (
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
)

// RestoreOption 调整恢复行为。
type RestoreOption func(*restoreCfg)

type restoreCfg struct {
	clockFn func() time.Time
}

// WithClock 为恢复出的摄取归一化器注入墙钟函数。
//
// 时钟不写入快照（生产环境恢复后理应使用新进程的真实墙钟）；该选项
// 服务于注入固定时钟的测试/离线复现场景，使其恢复后判定口径不变。
func WithClock(fn func() time.Time) RestoreOption {
	return func(c *restoreCfg) { c.clockFn = fn }
}

// EngineState 返回快照中的引擎状态（深拷贝语义：返回的是独立副本）。
func (s *Snapshot) EngineState() correlate.EngineState {
	return engineStateFromDTO(s.env.Engine)
}

// IngestState 返回快照中的摄取幂等状态（独立副本）。
func (s *Snapshot) IngestState() ingest.State {
	return ingestStateFromDTO(s.env.Ingest)
}

// Restore 校验快照内容并重建摄取服务与关联引擎，使其恢复到导出时刻的状态。
//
// 返回的引擎与摄取服务，与从未重启的进程在后续处理上结论一致：
// 已告警指纹保留（不重）、窗口内未凑齐序列随后续事件经全量 DP 重算（不漏）、
// 摄取幂等表保留（重复投递仍判 duplicate）、抑制桶恢复（静默期语义延续）、
// 规则携带导出时刻的版本（热更新语义照旧）。
//
// 内容校验失败返回 CodeInvalid 的 *Error，绝不静默接受损坏快照。
func (s *Snapshot) Restore(opts ...RestoreOption) (*ingest.Service, *correlate.Engine, error) {
	cfg := restoreCfg{}
	for _, o := range opts {
		o(&cfg)
	}
	if err := checkVersion(s.env.Version); err != nil {
		return nil, nil, err
	}
	engSt := engineStateFromDTO(s.env.Engine)
	if err := validateEngineState(engSt); err != nil {
		return nil, nil, err
	}

	inCfg := s.env.Ingest.Config
	norm := ingest.NewNormalizer(inCfg.MaxFutureSkew.std(), inCfg.MinAge.std())
	if cfg.clockFn != nil {
		norm.SetClock(cfg.clockFn)
	}
	svc := ingest.NewService(norm)
	svc.RestoreState(ingestStateFromDTO(s.env.Ingest))

	eng := correlate.NewEngine(engSt.Suppression, engSt.AllowedLateness)
	if err := eng.RestoreState(engSt); err != nil {
		return nil, nil, snapErr(CodeInvalid, s.env.Version, "restore engine: %v", err)
	}
	return svc, eng, nil
}

// validateEngineState 对快照内容做基本一致性校验，防止损坏/篡改快照
// 被静默接受后产生看似合理实则错误的结论。
func validateEngineState(st correlate.EngineState) error {
	seenRules := map[string]bool{}
	for _, ds := range st.Rules {
		if seenRules[ds.Rule.ID] {
			return snapErr(CodeInvalid, FormatVersion, "duplicate rule id %q in snapshot", ds.Rule.ID)
		}
		seenRules[ds.Rule.ID] = true
		if ds.Version < 0 {
			return snapErr(CodeInvalid, FormatVersion, "rule %q has negative version", ds.Rule.ID)
		}
	}
	for _, rid := range st.RuleOrder {
		if !seenRules[rid] {
			return snapErr(CodeInvalid, FormatVersion, "rule_order references missing rule %q", rid)
		}
	}
	return nil
}
