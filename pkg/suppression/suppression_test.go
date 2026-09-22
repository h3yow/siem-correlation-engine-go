package suppression

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/alert"
)

func TestSuppressAndReopen(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	sup := New(30 * time.Second)

	a1 := &alert.Alert{Fingerprint: "fp1"}
	a1 = sup.Apply(a1, now)
	if a1.Suppressed || a1.Count != 1 {
		t.Fatalf("首次告警应放行 count=1，实际 suppressed=%v count=%d", a1.Suppressed, a1.Count)
	}

	a2 := &alert.Alert{Fingerprint: "fp1"}
	a2 = sup.Apply(a2, now.Add(10*time.Second))
	if !a2.Suppressed || a2.Count != 2 {
		t.Fatalf("窗口内重复应被抑制 count=2，实际 suppressed=%v count=%d", a2.Suppressed, a2.Count)
	}
	t.Logf("窗口内第二次到达被聚合抑制 count=%d", a2.Count)

	a3 := &alert.Alert{Fingerprint: "fp1"}
	a3 = sup.Apply(a3, now.Add(41*time.Second))
	if a3.Suppressed {
		t.Fatalf("超过抑制窗口后应重新放行，实际仍被抑制")
	}
	t.Log("抑制窗口滑过后重新放行")

	// 不同指纹互不影响。
	b := &alert.Alert{Fingerprint: "fp2"}
	b = sup.Apply(b, now.Add(41*time.Second))
	if b.Suppressed {
		t.Fatal("不同指纹不应被聚合")
	}

	if n := sup.Evict(now.Add(72 * time.Second)); n != 2 {
		t.Fatalf("过期聚合状态应淘汰 2 个，实际 %d", n)
	}
	if _, _, _, ok := sup.Stats("fp1"); ok {
		t.Fatal("淘汰后不应再能查询到 fp1")
	}
}

func TestPermanentDedup(t *testing.T) {
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	sup := New(0) // 永久去重
	sup.Apply(&alert.Alert{Fingerprint: "p"}, now)
	a := sup.Apply(&alert.Alert{Fingerprint: "p"}, now.Add(999*time.Hour))
	if !a.Suppressed {
		t.Fatal("永久去重模式下任何重复都应被抑制")
	}
	if n := sup.Evict(now.Add(999 * time.Hour)); n != 0 {
		t.Fatalf("永久去重不应淘汰状态，实际淘汰 %d", n)
	}
}
