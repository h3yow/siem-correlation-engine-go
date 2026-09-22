package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// IngestResult 是单条记录摄取的确定性结果。
type IngestResult struct {
	Event    event.Event
	Rejected *event.RejectedRecord // 与 Event 互斥：要么接受要么带原因拒绝
}

// Accepted 表示记录是否被接受。
func (r IngestResult) Accepted() bool { return r.Rejected == nil }

// Service 是并发安全的摄取服务：解析 -> 校验 -> 幂等去重。
//
// 幂等：以 (format, 原始内容规范化哈希) 作为去重键，重复摄取返回
// ReasonDuplicate 而不是产生第二个事件，保证同一序列不会因重复投递而重复告警。
type Service struct {
	mu       sync.Mutex
	norm     *Normalizer
	seen     map[string]string // dedupKey -> eventID
	dupCount int
}

// NewService 构造摄取服务。
func NewService(norm *Normalizer) *Service {
	if norm == nil {
		norm = NewNormalizer(time.Hour, 0)
	}
	return &Service{
		norm: norm,
		seen: map[string]string{},
	}
}

// dedupKey 计算格式+内容的确定性指纹（去掉首尾空白，避免换行差异）。
func dedupKey(format, raw string) string {
	h := sha256.Sum256([]byte(format + "\x00" + trimSpace(raw)))
	return hex.EncodeToString(h[:16])
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\n' || s[0] == '\r' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

// Ingest 摄取一条原始记录，返回确定性结果。
func (s *Service) Ingest(raw string) IngestResult {
	seenAt := time.Now().UnixNano()

	format := DetectFormat(raw)
	if trimSpace(raw) == "" {
		return IngestResult{Rejected: &event.RejectedRecord{
			Raw: raw, Reason: event.ReasonEmpty, Detail: "empty record", SeenAtNs: seenAt,
		}}
	}
	if format == "" {
		return IngestResult{Rejected: &event.RejectedRecord{
			Raw: raw, Reason: event.ReasonUnsupportedFormat,
			Detail: "cannot detect json/syslog/keyvalue format", SeenAtNs: seenAt,
		}}
	}

	// 幂等去重需要在锁内完成，保证并发下同内容只接受一次。
	key := dedupKey(format, raw)
	s.mu.Lock()
	if existing, dup := s.seen[key]; dup {
		s.dupCount++
		s.mu.Unlock()
		return IngestResult{Rejected: &event.RejectedRecord{
			Raw: raw, Format: format, Reason: event.ReasonDuplicate,
			Detail: "duplicate of accepted event " + existing, SeenAtNs: seenAt,
		}}
	}
	s.mu.Unlock()

	parser := parsers[format]
	fields, err := parser.Parse(raw)
	if err != nil {
		return IngestResult{Rejected: &event.RejectedRecord{
			Raw: raw, Format: format, Reason: event.ReasonMalformed,
			Detail: err.Error(), SeenAtNs: seenAt,
		}}
	}

	ev, err := s.norm.Normalize(format, fields, raw)
	if err != nil {
		reason := event.ReasonMalformed
		var detail string
		if re, ok := err.(*event.RejectError); ok {
			reason = re.Record.Reason
			detail = re.Record.Detail
		} else {
			detail = err.Error()
		}
		return IngestResult{Rejected: &event.RejectedRecord{
			Raw: raw, Format: format, Reason: reason, Detail: detail, SeenAtNs: seenAt,
		}}
	}

	// 接受：在锁内登记幂等键。
	s.mu.Lock()
	if existing, dup := s.seen[key]; dup {
		// 罕见竞态兜底：Parse/Normalize 期间另一 goroutine 已登记同键。
		s.dupCount++
		s.mu.Unlock()
		return IngestResult{Rejected: &event.RejectedRecord{
			Raw: raw, Format: format, Reason: event.ReasonDuplicate,
			Detail: "duplicate of accepted event " + existing, SeenAtNs: seenAt,
		}}
	}
	s.seen[key] = ev.ID
	s.mu.Unlock()

	return IngestResult{Event: ev}
}

// IngestConcurrent 并发摄取多条记录。
//
// 无论 goroutine 调度顺序如何，返回结果都按以下确定性规则排序：
//  1. 接受事件在前、拒绝在后；
//  2. 接受事件按 (OccurredAt, ID) 排序；
//  3. 拒绝记录按 (Reason, Raw 指纹) 排序。
//
// 因此同一批输入在任意并发度下结论与顺序完全一致。
func (s *Service) IngestConcurrent(raws []string) []IngestResult {
	results := make([]IngestResult, len(raws))
	var wg sync.WaitGroup
	// 每个输入位置独立写自己的槽位，无数据竞争；去重一致性由 Service 内部锁保证。
	for i, raw := range raws {
		wg.Add(1)
		go func(i int, raw string) {
			defer wg.Done()
			results[i] = s.Ingest(raw)
		}(i, raw)
	}
	wg.Wait()
	sortResults(results)
	return results
}

func sortResults(results []IngestResult) {
	reasonRank := func(r IngestResult) int {
		if r.Accepted() {
			return 0
		}
		return 1
	}
	sort.SliceStable(results, func(i, j int) bool {
		ri, rj := reasonRank(results[i]), reasonRank(results[j])
		if ri != rj {
			return ri < rj
		}
		if ri == 0 {
			ei, ej := results[i].Event, results[j].Event
			if !ei.OccurredAt.Equal(ej.OccurredAt) {
				return ei.OccurredAt.Before(ej.OccurredAt)
			}
			return ei.ID < ej.ID
		}
		a, b := results[i].Rejected, results[j].Rejected
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		return dedupKey(a.Format, a.Raw) < dedupKey(b.Format, b.Raw)
	})
}

// Stats 返回接受/去重计数快照。
func (s *Service) Stats() (accepted, duplicated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen), s.dupCount
}
