package ingest

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
)

// TestExportRestoreStateKeepsDedup 跨"进程"导出/恢复去重表后，
// 重启前已接受的原始记录再次投递仍被判 duplicate，而不是新事件。
func TestExportRestoreStateKeepsDedup(t *testing.T) {
	norm := NewNormalizer(time.Hour, 0)
	svc1 := NewService(norm)

	raw := `{"timestamp":"2026-09-23T12:00:00Z","source":"sshd","event_type":"auth.failure","src_ip":"1.1.1.1"}`
	r1 := svc1.Ingest(raw)
	if !r1.Accepted() {
		t.Fatalf("首次投递应接受, got %v", r1.Rejected)
	}
	r1dup := svc1.Ingest(raw)
	if r1dup.Accepted() || r1dup.Rejected.Reason != event.ReasonDuplicate {
		t.Fatalf("同进程重复应为 duplicate, got %+v", r1dup)
	}

	seen, dup := svc1.ExportState()
	if dup != 1 || len(seen) != 1 {
		t.Fatalf("导出状态异常: seen=%d dup=%d", len(seen), dup)
	}

	// 模拟新进程：全新 Service 恢复去重表。
	svc2 := NewService(NewNormalizer(time.Hour, 0))
	if err := svc2.RestoreState(seen, dup); err != nil {
		t.Fatalf("restore: %v", err)
	}
	r2 := svc2.Ingest(raw)
	if r2.Accepted() || r2.Rejected.Reason != event.ReasonDuplicate {
		t.Fatalf("跨进程恢复后重复投递仍应 duplicate, got %+v", r2)
	}
	accepted2, dup2 := svc2.Stats()
	if accepted2 != 1 || dup2 != 2 {
		t.Fatalf("恢复后计数接续异常: accepted=%d dup=%d", accepted2, dup2)
	}
}

// TestRestoreStateRejectsInvalid 非法快照状态必须报错。
func TestRestoreStateRejectsInvalid(t *testing.T) {
	svc := NewService(nil)
	if err := svc.RestoreState(map[string]string{"": "evt-x"}, 0); err == nil {
		t.Fatal("空 dedup key 必须被拒绝")
	}
	if err := svc.RestoreState(map[string]string{"k": ""}, 0); err == nil {
		t.Fatal("空 event id 必须被拒绝")
	}
	if err := svc.RestoreState(nil, -1); err == nil {
		t.Fatal("负重复计数必须被拒绝")
	}
}
