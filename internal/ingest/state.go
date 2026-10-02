package ingest

import "fmt"

// ExportState 导出摄取层的幂等去重表（dedupKey -> eventID）与重复计数。
//
// 跨进程恢复它，重启前已接受过的记录在新进程里再次投递时，仍会得到
// duplicate 拒绝，而不是被当成新事件二次送入引擎——这是"重复投递跨
// 重启也不重不漏"的第一道保障（引擎侧的永久指纹集合是第二道）。
//
// 注意：时间判定口径不在这里返回，请用 ExportTimePolicy 单独导出，
// 由引擎层把两者一并写进快照。
func (s *Service) ExportState() (map[string]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.seen))
	for k, v := range s.seen {
		out[k] = v
	}
	return out, s.dupCount
}

// ExportTimePolicy 导出导出那一刻生效的事件时间判定口径
// （对未来事件的容忍范围、最早可回溯年龄）。它必须随快照一起走，
// 恢复后原样套用，不能在新进程里退回默认值。
func (s *Service) ExportTimePolicy() TimePolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.norm.TimePolicy()
}

// RestoreState 用快照中的去重表重建服务的幂等状态，并把事件时间判定口径
// 原样套用到归一化器——即使本服务构造时传入的是另一套（含默认）口径，
// 恢复后也一律以快照导出那一刻的 policy 为准，保证边界附近事件
// （刚好容忍/刚好超出 future skew、最早可回溯边界两侧）的接受/拒绝
// 结论与原进程逐条一致。
// 调用方应传入一个刚构造、尚未接收任何记录的 Service，避免混入进程内状态。
func (s *Service) RestoreState(seen map[string]string, dupCount int, policy TimePolicy) error {
	if dupCount < 0 {
		return fmt.Errorf("snapshot: invalid state: ingest dup_count must not be negative")
	}
	if policy.MaxFutureSkew < 0 {
		return fmt.Errorf("snapshot: invalid state: max_future_skew must not be negative")
	}
	if policy.MinAge < 0 {
		return fmt.Errorf("snapshot: invalid state: min_age must not be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// 先套口径再放状态：一旦返回错误，调用方不应把该服务投入使用，
	// 因此这里直接覆盖，保证恢复成功的服务口径必然等于快照口径。
	s.norm.ApplyTimePolicy(policy)
	s.seen = make(map[string]string, len(seen))
	for k, v := range seen {
		if k == "" || v == "" {
			return fmt.Errorf("snapshot: invalid state: ingest seen table has empty key/value")
		}
		s.seen[k] = v
	}
	s.dupCount = dupCount
	return nil
}
