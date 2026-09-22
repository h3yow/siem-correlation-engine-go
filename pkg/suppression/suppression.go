package suppression

import (
	"sync"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/alert"
)

type aggState struct {
	count   int
	firstAt time.Time
	lastAt  time.Time
}

// Suppressor 按指纹维度对重复/高频告警做聚合计数与时间抑制：
// 同一指纹在 dedupWindow 内首次到达正常告警，窗口内再次到达
// 被标记 Suppressed 且 Count 累加；窗口滑过后重新放行。
type Suppressor struct {
	mu          sync.Mutex
	dedupWindow time.Duration
	state       map[string]*aggState
}

func New(dedupWindow time.Duration) *Suppressor {
	if dedupWindow <= 0 {
		dedupWindow = 0
	}
	return &Suppressor{dedupWindow: dedupWindow, state: map[string]*aggState{}}
}

func (s *Suppressor) Apply(a *alert.Alert, now time.Time) *alert.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[a.Fingerprint]
	fresh := st == nil || (s.dedupWindow > 0 && now.Sub(st.lastAt) >= s.dedupWindow)
	if fresh {
		s.state[a.Fingerprint] = &aggState{count: 1, firstAt: now, lastAt: now}
		a.Suppressed = false
		a.Count = 1
		return a
	}
	st.count++
	st.lastAt = now
	a.Suppressed = true
	a.Count = st.count
	return a
}

func (s *Suppressor) Stats(fp string) (count int, firstAt, lastAt time.Time, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state[fp]
	if st == nil {
		return 0, time.Time{}, time.Time{}, false
	}
	return st.count, st.firstAt, st.lastAt, true
}

// Evict 淘汰上次出现时间早于 now-dedupWindow 的聚合状态，返回淘汰数。
// dedupWindow<=0 表示永久去重，不做淘汰。
func (s *Suppressor) Evict(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dedupWindow <= 0 {
		return 0
	}
	n := 0
	horizon := now.Add(-s.dedupWindow)
	for fp, st := range s.state {
		if st.lastAt.Before(horizon) {
			delete(s.state, fp)
			n++
		}
	}
	return n
}
