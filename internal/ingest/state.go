package ingest

import "fmt"

// ExportState 导出摄取层的幂等去重表（dedupKey -> eventID）与重复计数。
//
// 跨进程恢复它，重启前已接受过的记录在新进程里再次投递时，仍会得到
// duplicate 拒绝，而不是被当成新事件二次送入引擎——这是"重复投递跨
// 重启也不重不漏"的第一道保障（引擎侧的永久指纹集合是第二道）。
func (s *Service) ExportState() (map[string]string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.seen))
	for k, v := range s.seen {
		out[k] = v
	}
	return out, s.dupCount
}

// RestoreState 用快照中的去重表重建服务的幂等状态。
// 调用方应传入一个刚构造、尚未接收任何记录的 Service，避免混入进程内状态。
func (s *Service) RestoreState(seen map[string]string, dupCount int) error {
	if dupCount < 0 {
		return fmt.Errorf("snapshot: invalid state: ingest dup_count must not be negative")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
