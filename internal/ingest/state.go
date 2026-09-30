package ingest

import "time"

// State 是摄取服务的可快照状态：幂等去重表（dedupKey -> eventID）与计数。
//
// 恢复后，导出前已接受的原始记录再次投递仍会以 duplicate 拒绝，
// 从而保证"进程没重启过"的幂等语义跨进程延续。
type State struct {
	Seen     map[string]string
	DupCount int
}

// ExportState 深拷贝导出摄取服务的幂等状态。
func (s *Service) ExportState() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]string, len(s.seen))
	for k, v := range s.seen {
		seen[k] = v
	}
	return State{Seen: seen, DupCount: s.dupCount}
}

// RestoreState 用快照状态覆盖摄取服务的幂等状态（深拷贝入参）。
func (s *Service) RestoreState(st State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]string, len(st.Seen))
	for k, v := range st.Seen {
		seen[k] = v
	}
	s.seen = seen
	s.dupCount = st.DupCount
}

// MaxFutureSkew 返回归一化器允许的未来时钟偏移（快照恢复用）。
func (s *Service) MaxFutureSkew() time.Duration { return s.norm.MaxFutureSkew }

// MinAge 返回归一化器允许的最早回溯时长（快照恢复用）。
func (s *Service) MinAge() time.Duration { return s.norm.MinAge }

// SetClock 注入归一化器使用的墙钟函数（快照恢复后如需保持测试/演示
// 所用的固定时钟，可调用它；生产环境无需调用，默认即 time.Now）。
func (s *Service) SetClock(fn func() time.Time) { s.norm.SetClock(fn) }
