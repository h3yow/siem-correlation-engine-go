package rule

import (
	"sync"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// Store 是并发安全的规则存储；每次 Upsert/Delete 递增版本号，
// 引擎依据版本号感知规则变更。
type Store struct {
	mu    sync.RWMutex
	rules map[string]*Rule
	ver   int64
}

func NewStore() *Store {
	return &Store{rules: map[string]*Rule{}}
}

// Upsert 新增或更新规则（按 ID），返回变更后的存储版本。
func (s *Store) Upsert(r *Rule) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[r.ID] = cloneRule(r)
	s.ver++
	return s.ver
}

func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rules[id]; !ok {
		return false
	}
	delete(s.rules, id)
	s.ver++
	return true
}

func (s *Store) Get(id string) (*Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[id]
	if !ok {
		return nil, false
	}
	return cloneRule(r), true
}

// Snapshot 返回全部规则的副本，避免外部无锁修改。
func (s *Store) Snapshot() []*Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Rule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, cloneRule(r))
	}
	return out
}

func (s *Store) Version() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ver
}

func cloneRule(r *Rule) *Rule {
	if r == nil {
		return nil
	}
	cp := *r
	cp.GroupBy = append([]string(nil), r.GroupBy...)
	cp.Sequence = make([]Condition, len(r.Sequence))
	for i, c := range r.Sequence {
		cp.Sequence[i] = c
		if c.Attrs != nil {
			cp.Sequence[i].Attrs = make(map[string]string, len(c.Attrs))
			for k, v := range c.Attrs {
				cp.Sequence[i].Attrs[k] = v
			}
		}
		if c.Severity != nil {
			cp.Sequence[i].Severity = append([]event.Severity(nil), c.Severity...)
		}
	}
	return &cp
}
