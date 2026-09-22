package suppress

import (
	"sort"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/alert"
)

// Bucket 是一个活动的聚合抑制桶。
type Bucket struct {
	AggregateKey   string
	OpenedAt       time.Time
	QuietUntil     time.Time
	FirstAlertKey  string
	OccurrenceCnt  int
	SampleEventIDs []string
}

// Suppressor 按 AggregateKey 维护抑制桶。
//
// 规则（全部确定性、可解释）：
//   - 桶不存在或当前时间已超过 QuietUntil：本次为 Fired，（重新）开桶；
//   - 否则：本次为 Suppressed，抑制原因指向桶的首条告警 DedupKey，
//     仅累加 OccurrenceCnt，并按上限保留证据样本。
//
// 抑制只改变 Kind 与计数，不改变 DedupKey/RuleVersion/证据，因此结论可复现。
type Suppressor struct {
	quietFor       time.Duration
	maxOccurrences int
	buckets        map[string]*Bucket
}

// New 构造抑制器。
func New(quietFor time.Duration, maxOccurrences int) *Suppressor {
	if maxOccurrences <= 0 {
		maxOccurrences = 100
	}
	return &Suppressor{
		quietFor:       quietFor,
		maxOccurrences: maxOccurrences,
		buckets:        map[string]*Bucket{},
	}
}

// Apply 对候选 Fired 告警应用抑制策略。
func (s *Suppressor) Apply(a alert.Alert, now time.Time) alert.Alert {
	key := a.AggregateKey
	if key == "" {
		key = "rule=" + a.RuleID
	}
	b := s.buckets[key]

	// 桶不存在或静默期已过：发出新告警并开新桶。
	if b == nil || !now.Before(b.QuietUntil) {
		s.buckets[key] = &Bucket{
			AggregateKey:   key,
			OpenedAt:       now,
			QuietUntil:     now.Add(s.quietFor),
			FirstAlertKey:  a.DedupKey,
			OccurrenceCnt:  1,
			SampleEventIDs: sampleIDs(a, s.maxOccurrences),
		}
		a.Kind = alert.KindFired
		a.AggregateKey = key
		a.OccurrenceCnt = 1
		a.SuppressedBy = ""
		return a
	}

	// 在静默期内：抑制，聚合到首条告警，计数与样本可解释地累计。
	b.OccurrenceCnt++
	if len(b.SampleEventIDs) < s.maxOccurrences {
		b.SampleEventIDs = append(b.SampleEventIDs, a.EventIDs()...)
		if len(b.SampleEventIDs) > s.maxOccurrences {
			b.SampleEventIDs = b.SampleEventIDs[:s.maxOccurrences]
		}
	}
	a.Kind = alert.KindSuppressed
	a.AggregateKey = key
	a.OccurrenceCnt = b.OccurrenceCnt
	a.SuppressedBy = b.FirstAlertKey
	return a
}

func sampleIDs(a alert.Alert, max int) []string {
	ids := a.EventIDs()
	if len(ids) > max {
		ids = ids[:max]
	}
	return ids
}

// Buckets 返回按 AggregateKey 排序的桶快照（确定性顺序，便于日志）。
func (s *Suppressor) Buckets() []Bucket {
	out := make([]Bucket, 0, len(s.buckets))
	for _, b := range s.buckets {
		cp := Bucket{
			AggregateKey:   b.AggregateKey,
			OpenedAt:       b.OpenedAt,
			QuietUntil:     b.QuietUntil,
			FirstAlertKey:  b.FirstAlertKey,
			OccurrenceCnt:  b.OccurrenceCnt,
			SampleEventIDs: append([]string{}, b.SampleEventIDs...),
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AggregateKey < out[j].AggregateKey })
	return out
}

// Reset 清空全部抑制状态。
func (s *Suppressor) Reset() {
	s.buckets = map[string]*Bucket{}
}
