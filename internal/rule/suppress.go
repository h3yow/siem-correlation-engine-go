package rule

import (
	"strings"
	"time"
)

// SuppressionConfig 描述告警抑制策略。
//
// 聚合维度 AggregateBy 可取值：rule_id / rule_id+src_ip / rule_id+user /
// rule_id+src_ip+dst_ip 等，由 correlate 层解析为告警上的 AggregateKey。
//
// 策略：在 QuietFor 时长内，同一 AggregateKey 的后续命中不产生新 Fired，
// 只对首条告警累计 OccurrenceCnt（可解释的频次聚合）；
// QuietFor 过后再次命中则产生新 Fired 并开启新的抑制窗口。
// MaxOccurrences > 0 时，聚合桶最多记录该数量的证据样本。
type SuppressionConfig struct {
	AggregateBy    []string
	QuietFor       time.Duration
	MaxOccurrences int
}

// DefaultSuppression 返回默认抑制配置（按 rule+src_ip 聚合，抑制 5 分钟）。
func DefaultSuppression() SuppressionConfig {
	return SuppressionConfig{
		AggregateBy:    []string{"rule_id", "src_ip"},
		QuietFor:       5 * time.Minute,
		MaxOccurrences: 100,
	}
}

// AggregateKey 按配置维度计算聚合键。
//
// groupDim/groupValue 是规则 GroupBy 维度及其取值（规则未分组时 groupDim 为 ""、
// groupValue 为 "_"）。只有同时出现在 AggregateBy 中的维度才参与键，
// 未配置的维度被确定性忽略。该键决定抑制桶身份，也是告警上的可解释聚合维度。
func AggregateKey(cfg SuppressionConfig, ruleID, groupDim, groupValue string) string {
	parts := make([]string, 0, len(cfg.AggregateBy))
	for _, dim := range cfg.AggregateBy {
		switch dim {
		case "rule_id":
			parts = append(parts, "rule="+ruleID)
		case groupDim:
			parts = append(parts, dim+"="+groupValue)
		default:
			// 该维度不是规则分组维度（或规则未分组），不参与聚合。
			continue
		}
	}
	return strings.Join(parts, "|")
}
