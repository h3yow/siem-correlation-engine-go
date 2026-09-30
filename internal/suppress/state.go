package suppress

import "time"

// State 是抑制器的可快照状态：配置与全部活动聚合桶。
type State struct {
	QuietFor       time.Duration
	MaxOccurrences int
	Buckets        []Bucket
}

// ExportState 深拷贝导出抑制器状态。
//
// 调用方（correlate.Engine）持有引擎级互斥锁时调用，因此这里不再加锁；
// 导出对桶内切片做拷贝，快照可脱离引擎长期持有、序列化，且不会与
// 后续摄取共享底层内存（反复导出不会累积内存）。
func (s *Suppressor) ExportState() State {
	return State{
		QuietFor:       s.quietFor,
		MaxOccurrences: s.maxOccurrences,
		Buckets:        s.Buckets(), // Buckets 已做深拷贝并按 key 排序
	}
}

// RestoreState 用快照状态覆盖抑制器内部状态（深拷贝入参）。
func (s *Suppressor) RestoreState(st State) {
	maxOcc := st.MaxOccurrences
	if maxOcc <= 0 {
		maxOcc = 100
	}
	buckets := make(map[string]*Bucket, len(st.Buckets))
	for _, b := range st.Buckets {
		cp := b
		cp.SampleEventIDs = append([]string{}, b.SampleEventIDs...)
		buckets[b.AggregateKey] = &cp
	}
	s.quietFor = st.QuietFor
	s.maxOccurrences = maxOcc
	s.buckets = buckets
}
