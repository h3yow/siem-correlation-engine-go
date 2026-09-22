package parser

import (
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

func TestParseFormats(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewJSONParser())
	reg.Register(NewKVParser())
	reg.Register(NewCSVParser())

	cases := []struct {
		name    string
		line    string
		id      string
		typ     string
		subject string
		sev     event.Severity
	}{
		{"json", `{"id":"j1","ts":"2026-09-23T10:00:00Z","type":"auth.login","severity":"high","subject":"bob","attrs":{"ip":"1.1.1.1"}}`, "j1", "auth.login", "bob", event.SeverityHigh},
		{"json-unix", `{"id":"j2","ts":1789000000,"type":"x","severity":"warn"}`, "j2", "x", "", event.SeverityMedium},
		{"kv", `id=k1 ts=2026-09-23T10:00:00Z type=net.deny severity=critical subject="carol d" region=us`, "k1", "net.deny", "carol d", event.SeverityCritical},
		{"csv", `c1,2026-09-23T10:00:00Z,audit.view,low,dave,opened file`, "c1", "audit.view", "dave", event.SeverityLow},
	}
	want := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, fname, err := reg.ParseAuto(tc.line, "src")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Logf("格式=%s 解析出事件 id=%s type=%s ts=%s", fname, ev.ID, ev.Type, ev.Timestamp)
			if ev.ID != tc.id || ev.Type != tc.typ || ev.Subject != tc.subject || ev.Severity != tc.sev {
				t.Fatalf("字段不匹配: %+v", ev)
			}
			if tc.name != "json-unix" && !ev.Timestamp.Equal(want) {
				t.Fatalf("时间戳解析错误: got %s", ev.Timestamp)
			}
		})
	}
}

func TestRejectReasons(t *testing.T) {
	reg := NewRegistry()
	reg.Register(NewJSONParser())
	reg.Register(NewKVParser())
	reg.Register(NewCSVParser())

	cases := []struct {
		line   string
		reason event.RejectReason
	}{
		{"   ", event.RejectEmpty},
		{"plain text no structure", event.RejectUnsupportedFmt},
		{`{"id":"x","ts":"2026-09-23T10:00:00Z"}`, event.RejectMissingType},
		{`{"ts":"2026-09-23T10:00:00Z","type":"t"}`, event.RejectMissingID},
		{`{"id":"x","type":"t"}`, event.RejectMissingTime},
		{`{"id":"x","ts":"nonsense","type":"t"}`, event.RejectBadTimestamp},
		{`{"id":"x","ts":"2099-01-01T00:00:00Z","type":"t"}`, event.RejectFutureTime},
		{`{"id":"x","ts":"2000-01-01T00:00:00Z","type":"t"}`, event.RejectTooOld},
		{`{bad json`, event.RejectMalformed},
		{`id=x ts=bogus type=t`, event.RejectBadTimestamp},
		{`a,b,c`, event.RejectMalformed},
	}
	now := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	v := NewValidator(60, 3600)
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			ev, _, err := reg.ParseAuto(tc.line, "src")
			if err != nil {
				pe, ok := err.(*ParseError)
				if !ok {
					t.Fatalf("期望 ParseError，实际 %T", err)
				}
				if pe.Reason != tc.reason {
					t.Fatalf("期望原因 %s，实际 %s (%s)", tc.reason, pe.Reason, pe.Detail)
				}
				t.Logf("记录 %q 被拒绝，原因=%s 明细=%s", tc.line, pe.Reason, pe.Detail)
				return
			}
			if err := v.Validate(ev, now); err != nil {
				pe := err.(*ParseError)
				if pe.Reason != tc.reason {
					t.Fatalf("校验原因期望 %s，实际 %s", tc.reason, pe.Reason)
				}
				t.Logf("记录 %q 通过解析但校验拒绝，原因=%s", tc.line, pe.Reason)
				return
			}
			t.Fatalf("记录 %q 应被拒绝(%s)，但被接受", tc.line, tc.reason)
		})
	}
}
