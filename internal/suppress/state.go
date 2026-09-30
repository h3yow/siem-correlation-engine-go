package suppress

import (
	"fmt"
	"sort"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

func errSnapshotState(format string, args ...any) error {
	return fmt.Errorf("snapshot: invalid state: "+format, args...)
}

// ExportState 导出抑制器配置与全部活动桶（含静默截止、首告警指纹、
// 累计计数与证据样本），恢复后抑制窗口语义与未重启完全一致。
func (s *Suppressor) ExportState() snapshot.SuppressorState {
	st := snapshot.SuppressorState{
		QuietFor:       snapshot.DurationJSON(s.quietFor),
		MaxOccurrences: s.maxOccurrences,
	}
	keys := make([]string, 0, len(s.buckets))
	for k := range s.buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := s.buckets[k]
		st.Buckets = append(st.Buckets, snapshot.BucketState{
			AggregateKey:   b.AggregateKey,
			OpenedAt:       b.OpenedAt.UTC(),
			QuietUntil:     b.QuietUntil.UTC(),
			FirstAlertKey:  b.FirstAlertKey,
			OccurrenceCnt:  b.OccurrenceCnt,
			SampleEventIDs: append([]string{}, b.SampleEventIDs...),
		})
	}
	return st
}

// RestoreSuppressor 从快照重建抑制器并校验结构。
func RestoreSuppressor(st snapshot.SuppressorState) (*Suppressor, error) {
	if st.QuietFor < 0 {
		return nil, errSnapshotState("suppressor quiet_for must not be negative")
	}
	s := New(time.Duration(st.QuietFor), st.MaxOccurrences)
	seen := map[string]bool{}
	for _, b := range st.Buckets {
		if b.AggregateKey == "" {
			return nil, errSnapshotState("suppressor bucket with empty key")
		}
		if seen[b.AggregateKey] {
			return nil, errSnapshotState("suppressor bucket %q duplicated", b.AggregateKey)
		}
		seen[b.AggregateKey] = true
		if b.OccurrenceCnt < 1 {
			return nil, errSnapshotState("suppressor bucket %q occurrence_cnt must be >= 1", b.AggregateKey)
		}
		if b.FirstAlertKey == "" {
			return nil, errSnapshotState("suppressor bucket %q missing first_alert_key", b.AggregateKey)
		}
		s.buckets[b.AggregateKey] = &Bucket{
			AggregateKey:   b.AggregateKey,
			OpenedAt:       b.OpenedAt.UTC(),
			QuietUntil:     b.QuietUntil.UTC(),
			FirstAlertKey:  b.FirstAlertKey,
			OccurrenceCnt:  b.OccurrenceCnt,
			SampleEventIDs: append([]string{}, b.SampleEventIDs...),
		}
	}
	return s, nil
}
