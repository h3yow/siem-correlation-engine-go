package ingest

import (
	"fmt"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

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

// Policy 导出摄取层当前的事件时间判定口径（未来容忍范围、最早回溯年龄）。
// 它必须随快照一起持久化：否则新进程会退回自己构造 Normalizer 时传入的
// （通常是默认）口径，导致重启前后边界附近 future_event/too_old 结论漂移。
func (s *Service) Policy() snapshot.TimePolicy {
	s.mu.Lock()
	defer s.mu.Unlock()
	future, minAge := s.norm.Policy()
	return snapshot.TimePolicy{
		MaxFutureSkew: snapshot.DurationJSON(future),
		MinAge:        snapshot.DurationJSON(minAge),
	}
}

// ApplyTimePolicy 用快照里的口径强制覆盖本服务归一化器的口径。
// 跨进程恢复时调用：调用方构造 Service 时传入的口径一律被快照口径覆盖，
// 保证恢复后的边界判定与导出那一刻逐条一致。时钟函数保持不变（由调用方
// 在恢复后按其运行环境重新注入），时钟不属于要持久化的业务口径。
func (s *Service) ApplyTimePolicy(p snapshot.TimePolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.norm.ApplyPolicy(time.Duration(p.MaxFutureSkew), time.Duration(p.MinAge))
	return nil
}
