package snapshot_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/snapshot"
)

func seededSnapshot(t *testing.T) *snapshot.Snapshot {
	t.Helper()
	env := newTestEnv(30 * time.Second)
	if err := env.eng.UpsertRule(bruteForceRule(10*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	env.feed(t, []event.Event{fail(0, "1.1.1.1"), fail(1, "1.1.1.1")})
	snap := snapshot.Export(env.svc, env.eng, snapshot.WithTakenAt(testBase))
	return snap
}

// TestVersionReasonsAreDistinguishable 各类无法读取的快照必须返回
// 可区分的错误码，绝不静默读入。
func TestVersionReasonsAreDistinguishable(t *testing.T) {
	snap := seededSnapshot(t)
	good, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		mutate func(b []byte) []byte
		want   snapshot.ErrorCode
	}{
		{
			name:   "not a snapshot (foreign json)",
			mutate: func(b []byte) []byte { return []byte(`{"hello":"world"}`) },
			want:   snapshot.CodeNotSnapshot,
		},
		{
			name:   "not a snapshot (plain text)",
			mutate: func(b []byte) []byte { return []byte("this is not json at all") },
			want:   snapshot.CodeNotSnapshot,
		},
		{
			name: "corrupt json with snapshot magic",
			mutate: func(b []byte) []byte {
				// format 字段仍可读，但把 version 改成非法类型：
				// 宽松探测认得出 magic，完整解析失败 => corrupt（而非 not_a_snapshot）。
				return setVersionRaw(t, b, `"not-a-number"`)
			},
			want: snapshot.CodeCorrupt,
		},
		{
			name: "newer version rejected",
			mutate: func(b []byte) []byte {
				return setVersion(t, b, snapshot.FormatVersion+1)
			},
			want: snapshot.CodeUnsupportedVersion,
		},
		{
			name: "too old version rejected (needs migration)",
			mutate: func(b []byte) []byte {
				return setVersion(t, b, snapshot.MinSupportedVersion-1)
			},
			want: snapshot.CodeIncompatibleVersion,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := snapshot.Decode(tc.mutate(good))
			var se *snapshot.Error
			if !errors.As(err, &se) {
				t.Fatalf("want *snapshot.Error, got %v", err)
			}
			if se.Code != tc.want {
				t.Fatalf("want code %s, got %s (err=%v)", tc.want, se.Code, err)
			}
			if !strings.Contains(err.Error(), string(tc.want)) {
				t.Fatalf("error message should carry code, got %q", err.Error())
			}
			t.Logf("版本/格式拒绝原因可区分: code=%s version=%d", se.Code, se.Version)
		})
	}
}

func setVersion(t *testing.T, b []byte, v int) []byte {
	t.Helper()
	return setVersionRaw(t, b, strconv.Itoa(v))
}

func setVersionRaw(t *testing.T, b []byte, raw string) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["version"] = json.RawMessage(raw)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCurrentVersionRoundTrips 当前版本快照可以被自身读取并完整恢复。
func TestCurrentVersionRoundTrips(t *testing.T) {
	snap := seededSnapshot(t)
	if snap.Version() != snapshot.FormatVersion {
		t.Fatalf("want version %d, got %d", snapshot.FormatVersion, snap.Version())
	}
	data, err := snap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := snapshot.Decode(data)
	if err != nil {
		t.Fatalf("current version must decode: %v", err)
	}
	svc, eng, err := got.Restore()
	if err != nil {
		t.Fatalf("current version must restore: %v", err)
	}
	if eng.Watermark() != snap.EngineState().Watermark {
		t.Fatal("watermark mismatch after roundtrip")
	}
	if accepted, _ := svc.Stats(); accepted == 0 {
		t.Fatal("ingest dedup table should be restored")
	}
}

// TestSaveLoadAtomic 落盘后可读取恢复；目标路径读到的永远是完整快照。
func TestSaveLoadAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "engine.snap.json")

	snap := seededSnapshot(t)
	if err := snap.SaveTo(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("snapshot file missing: %v", err)
	}
	loaded, err := snapshot.LoadFrom(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Version() != snapshot.FormatVersion {
		t.Fatalf("loaded version = %d", loaded.Version())
	}
	if !loaded.TakenAt().Equal(testBase) {
		t.Fatalf("taken_at not restored: %s", loaded.TakenAt())
	}
	if _, _, err := loaded.Restore(); err != nil {
		t.Fatalf("restore from disk: %v", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Fatalf("临时文件未清理: %s", e.Name())
		}
	}
}

// TestRepeatedExportIsDeterministicAndStable 周期性反复导出：
// 字节内容确定（重复导出逐字节一致），且导出后引擎继续处理结论不受影响。
func TestRepeatedExportIsDeterministicAndStable(t *testing.T) {
	env := newTestEnv(30 * time.Second)
	_ = env.eng.UpsertRule(bruteForceRule(10*time.Second), 1)
	env.feed(t, []event.Event{fail(0, "1.1.1.1"), fail(1, "1.1.1.1")})

	fixed := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	var first []byte
	for i := 0; i < 5; i++ {
		snap := snapshot.Export(env.svc, env.eng, snapshot.WithTakenAt(fixed))
		data, err := snap.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = data
		} else if string(data) != string(first) {
			t.Fatalf("第 %d 次导出与首次不一致（字节不确定）", i+1)
		}
	}
	// 导出 5 次后继续喂事件：序列照常补齐、只告警一次。
	env.feed(t, []event.Event{fail(2, "1.1.1.1"), locked(3, "1.1.1.1")})
	if got := countFired(env.alerts); got != 1 {
		t.Fatalf("repeated export must not disturb ingestion, fired=%d", got)
	}
}
