package ingest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

func fixedClock() func() time.Time {
	return func() time.Time {
		return time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	}
}

func newTestService() *Service {
	n := NewNormalizer(time.Hour, 0)
	n.nowFn = fixedClock()
	return NewService(n)
}

func mustAccepted(t *testing.T, svc *Service, raw string) event.Event {
	t.Helper()
	r := svc.Ingest(raw)
	if !r.Accepted() {
		t.Fatalf("expected accepted, got reject reason=%s detail=%s raw=%s",
			r.Rejected.Reason, r.Rejected.Detail, raw)
	}
	return r.Event
}

func mustReject(t *testing.T, svc *Service, raw string, want event.Reason) {
	t.Helper()
	r := svc.Ingest(raw)
	if r.Accepted() {
		t.Fatalf("expected reject %s, but accepted event %s (raw=%s)", want, r.Event.ID, raw)
	}
	if r.Rejected.Reason != want {
		t.Fatalf("expected reject reason=%s, got=%s (%s) raw=%s",
			want, r.Rejected.Reason, r.Rejected.Detail, raw)
	}
	t.Logf("拒绝记录 reason=%-18s detail=%q", r.Rejected.Reason, r.Rejected.Detail)
}

func TestParseThreeFormats(t *testing.T) {
	svc := newTestService()
	base := fixedClock()().Add(-time.Minute)
	b := base.Format(time.RFC3339)

	jsonEv := mustAccepted(t, svc,
		fmt.Sprintf(`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":"1.1.1.1","user":"root","action":"login_failed"}`, b))
	if jsonEv.SrcIP != "1.1.1.1" || jsonEv.User != "root" || jsonEv.EventType != "auth.failure" {
		t.Fatalf("json normalize wrong: %+v", jsonEv)
	}

	kvEv := mustAccepted(t, svc,
		fmt.Sprintf(`timestamp=%q source=firewall event_type=net.deny src_ip=2.2.2.2 dst_ip=10.0.0.1 action=deny`, b))
	if kvEv.Source != "firewall" || kvEv.Action != "deny" || kvEv.DstIP != "10.0.0.1" {
		t.Fatalf("kv normalize wrong: %+v", kvEv)
	}

	sysEv := mustAccepted(t, svc,
		fmt.Sprintf("%s web-01 sshd[901]: Failed password for root from 3.3.3.3 port 51000", b))
	if sysEv.Source != "sshd" || sysEv.SrcHost != "web-01" || sysEv.SrcIP != "3.3.3.3" || sysEv.EventType != "auth.failure" {
		t.Fatalf("syslog normalize wrong: %+v", sysEv)
	}
	t.Logf("三种格式归一化成功: json=%s kv=%s syslog=%s", jsonEv.ID, kvEv.ID, sysEv.ID)
}

func TestRejectReasonsAreDistinguishable(t *testing.T) {
	svc := newTestService()
	b := fixedClock()().Add(-time.Minute).Format(time.RFC3339)

	mustReject(t, svc, "", event.ReasonEmpty)
	mustReject(t, svc, "   \n\t ", event.ReasonEmpty)
	mustReject(t, svc, "hello world not a log", event.ReasonUnsupportedFormat)
	mustReject(t, svc, `{"timestamp":"`+b+`","source":`, event.ReasonMalformed)
	mustReject(t, svc, `{"source":"sshd","event_type":"auth.failure"}`, event.ReasonMissingTimestamp)
	mustReject(t, svc, `{"timestamp":"yesterday-ish","source":"sshd","event_type":"auth.failure"}`, event.ReasonBadTimestamp)
	mustReject(t, svc,
		`{"timestamp":"`+b+`","event_type":"auth.failure"}`, event.ReasonMissingEventTime)
	mustReject(t, svc,
		`{"timestamp":"`+fixedClock()().Add(2*time.Hour).Format(time.RFC3339)+`","source":"sshd","event_type":"auth.failure"}`,
		event.ReasonFutureEvent)
}

func TestIdempotentDuplicate(t *testing.T) {
	svc := newTestService()
	b := fixedClock()().Add(-time.Minute).Format(time.RFC3339)
	raw := fmt.Sprintf(`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":"9.9.9.9"}`, b)

	first := mustAccepted(t, svc, raw)
	mustReject(t, svc, raw, event.ReasonDuplicate)
	mustReject(t, svc, "  "+raw+"\n", event.ReasonDuplicate) // 首尾空白不影响指纹
	accepted, dup := svc.Stats()
	if accepted != 1 || dup != 2 {
		t.Fatalf("stats want accepted=1 duplicated=2, got %d/%d", accepted, dup)
	}
	t.Logf("幂等去重生效: 保留事件 %s，重复投递 2 次均被标记 duplicate", first.ID)
}

func TestConcurrentIngestIsDeterministic(t *testing.T) {
	b := fixedClock()().Add(-time.Minute)
	raws := []string{
		fmt.Sprintf(`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":"1.1.1.1"}`, b.Add(3*time.Second).Format(time.RFC3339)),
		fmt.Sprintf(`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":"2.2.2.2"}`, b.Add(1*time.Second).Format(time.RFC3339)),
		"",
		"garbled line",
		fmt.Sprintf(`{"timestamp":%q,"source":"sshd","event_type":"auth.failure","src_ip":"1.1.1.1"}`, b.Add(3*time.Second).Format(time.RFC3339)), // dup
		fmt.Sprintf(`{"timestamp":%q,"source":"sshd","event_type":"auth.success","src_ip":"3.3.3.3"}`, b.Add(2*time.Second).Format(time.RFC3339)),
	}

	var mu sync.Mutex
	snapshots := map[string]bool{}
	for run := 0; run < 20; run++ {
		svc := newTestService()
		res := svc.IngestConcurrent(raws)
		key := resultSignature(res)
		mu.Lock()
		snapshots[key] = true
		mu.Unlock()
	}
	if len(snapshots) != 1 {
		t.Fatalf("并发摄取结果不确定，出现 %d 种不同结论", len(snapshots))
	}

	svc := newTestService()
	res := svc.IngestConcurrent(raws)
	var accepted, rejected int
	for _, r := range res {
		if r.Accepted() {
			accepted++
		} else {
			rejected++
			t.Logf("并发批拒绝: reason=%s detail=%q", r.Rejected.Reason, r.Rejected.Detail)
		}
	}
	if accepted != 3 || rejected != 3 {
		t.Fatalf("want accepted=3 rejected=3, got %d/%d", accepted, rejected)
	}
	// 顺序确定性：接受事件必须按事件时间升序。
	var prev time.Time
	for _, r := range res {
		if !r.Accepted() {
			continue
		}
		if r.Event.OccurredAt.Before(prev) {
			t.Fatalf("accepted events not time-sorted: %s after %s", r.Event.OccurredAt, prev)
		}
		prev = r.Event.OccurredAt
	}
	t.Log("并发摄取 20 轮结论完全一致：3 接受（时间有序）/ 3 拒绝（empty/unsupported/duplicate）")
}

func resultSignature(rs []IngestResult) string {
	var s string
	for _, r := range rs {
		if r.Accepted() {
			s += "A:" + r.Event.ID + "@" + r.Event.OccurredAt.Format(time.RFC3339Nano) + ";"
		} else {
			s += "R:" + string(r.Rejected.Reason) + ":" + r.Rejected.Raw + ";"
		}
	}
	return s
}
