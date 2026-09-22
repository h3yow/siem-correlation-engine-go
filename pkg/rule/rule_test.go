package rule

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

func TestConditionMatch(t *testing.T) {
	ev := &event.Event{
		Type: "auth.login_failed", Source: "app1",
		Severity: event.SeverityHigh, Subject: "bob",
		Attrs: map[string]string{"ip": "10.0.0.1", "region": "us"},
	}
	cases := []struct {
		name string
		c    Condition
		want bool
	}{
		{"type", Condition{Type: "auth.login_failed"}, true},
		{"type-miss", Condition{Type: "auth.success"}, false},
		{"wildcard", Condition{Type: "*", Source: "app1"}, true},
		{"source-miss", Condition{Type: "*", Source: "app2"}, false},
		{"severity", Condition{Type: "*", Severity: []event.Severity{event.SeverityHigh}}, true},
		{"severity-miss", Condition{Type: "*", Severity: []event.Severity{event.SeverityLow}}, false},
		{"attr-ip", Condition{Type: "*", Attrs: map[string]string{"ip": "10.0.0.1"}}, true},
		{"attr-subject", Condition{Type: "*", Attrs: map[string]string{"subject": "bob"}}, true},
		{"attr-miss", Condition{Type: "*", Attrs: map[string]string{"ip:": "x"}}, false},
		{"attr-missing-key", Condition{Type: "*", Attrs: map[string]string{"zone": "x"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.Match(ev); got != tc.want {
				t.Fatalf("Match()=%v want %v", got, tc.want)
			}
		})
	}
}

func TestPartitionKey(t *testing.T) {
	r := &Rule{ID: "r", GroupBy: []string{"subject", "region"}}
	ev := &event.Event{Subject: "bob", Attrs: map[string]string{"region": "us"}}
	if k := r.PartitionKey(ev); k != "bob\x00us" {
		t.Fatalf("分区键错误: %q", k)
	}
	r2 := &Rule{ID: "r2"}
	if k := r2.PartitionKey(ev); k != "" {
		t.Fatalf("无 GroupBy 时分区键应为空: %q", k)
	}
}

func TestValidate(t *testing.T) {
	bad := []*Rule{
		{},
		{ID: "r"},
		{ID: "r", Window: time.Second},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Fatalf("非法规则 #%d 应报错", i)
		}
	}
	good := &Rule{ID: "r", Window: time.Second, Sequence: []Condition{{Type: "x"}}}
	if err := good.Validate(); err != nil {
		t.Fatalf("合法规则不应报错: %v", err)
	}
}

func TestStoreSnapshotIsolation(t *testing.T) {
	s := NewStore()
	r := &Rule{ID: "r", Window: time.Second, Sequence: []Condition{{Type: "x"}}, GroupBy: []string{"a"}}
	s.Upsert(r)
	snap := s.Snapshot()[0]
	snap.GroupBy[0] = "mutated"
	again, _ := s.Get("r")
	if again.GroupBy[0] != "a" {
		t.Fatal("快照修改不应影响存储内规则")
	}
	if v1 := s.Upsert(r); v1 != 2 {
		t.Fatalf("版本号应递增，实际 %d", v1)
	}
	if !s.Delete("r") || s.Delete("r") {
		t.Fatal("删除语义错误")
	}
}
