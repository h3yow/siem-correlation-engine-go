package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleState() State {
	return State{
		EngineID:        "eng-1",
		AllowedLateness: DurationJSON(30 * time.Second),
		Watermark:       time.Date(2026, 9, 23, 12, 0, 3, 0, time.UTC),
		RuleOrder:       []string{"r1"},
		Rules: []RuleState{{
			ID:      "r1",
			Version: 2,
			Rule: RuleDef{
				ID: "r1", Name: "n", Severity: "high",
				Pattern: []MatchDef{{EventType: "auth.failure"}},
				Window:  DurationJSON(10 * time.Second),
			},
			Fired: []string{"a>b"},
			Groups: []GroupState{{
				Key: "1.1.1.1",
				Events: []EventState{{
					ID: "evt-1", OccurredAt: time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
					Source: "sshd", EventType: "auth.failure", Severity: "high",
				}},
			}},
		}},
		Suppression: SuppressorState{
			AggregateBy:    []string{"rule_id", "src_ip"},
			QuietFor:       DurationJSON(time.Minute),
			MaxOccurrences: 10,
			Buckets: []BucketState{{
				AggregateKey:  "rule=r1",
				OpenedAt:      time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC),
				QuietUntil:    time.Date(2026, 9, 23, 12, 1, 0, 0, time.UTC),
				FirstAlertKey: "a>b", OccurrenceCnt: 1,
			}},
		},
		IngestSeen:     map[string]string{"dedup1": "evt-1"},
		IngestDupCount: 0,
		TimePolicy: &TimePolicyState{
			MaxFutureSkew: DurationJSON(90 * time.Second),
			MinAge:        DurationJSON(24 * time.Hour),
		},
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	st := sampleState()
	data, err := Encode(st, "eng-1")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.EngineID != "eng-1" || len(got.Rules) != 1 || got.Rules[0].Version != 2 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Rules[0].Rule.Severity != "high" {
		t.Fatalf("severity should survive as name, got %q", got.Rules[0].Rule.Severity)
	}
	if len(got.IngestSeen) != 1 || got.IngestSeen["dedup1"] != "evt-1" {
		t.Fatalf("ingest seen not restored: %+v", got.IngestSeen)
	}
}

func TestDecodeRejectsFutureVersion(t *testing.T) {
	st := sampleState()
	data, err := Encode(st, "eng-1")
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.FormatVersion = CurrentFormatVersion + 1
	bad, _ := json.Marshal(&env)
	_, err = Decode(bad)
	if err == nil {
		t.Fatal("future version must be rejected")
	}
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
	var ve *VersionError
	if !errors.As(err, &ve) {
		t.Fatalf("want *VersionError for distinguishable reason, got %T %v", err, err)
	}
	if ve.Got != CurrentFormatVersion+1 || ve.Min != MinSupportedVersion || ve.Max != CurrentFormatVersion {
		t.Fatalf("version error details wrong: %+v", ve)
	}
}

func TestDecodeRejectsOldVersion(t *testing.T) {
	st := sampleState()
	data, _ := Encode(st, "eng-1")
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.FormatVersion = 0
	bad, _ := json.Marshal(&env)
	_, err := Decode(bad)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version 0 must be unsupported, got %v", err)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	if _, err := Decode([]byte("{not json")); !errors.Is(err, ErrMalformedSnapshot) {
		t.Fatalf("want ErrMalformedSnapshot, got %v", err)
	}
	if _, err := Decode(nil); !errors.Is(err, ErrMalformedSnapshot) {
		t.Fatalf("empty input want ErrMalformedSnapshot, got %v", err)
	}
}

func TestDecodeRejectsTamperedState(t *testing.T) {
	st := sampleState()
	data, _ := Encode(st, "eng-1")
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	// 篡改状态但保留原 checksum：必须被明确识别为校验失败。
	env.State.Rules[0].Fired = []string{"forged"}
	tampered, _ := json.Marshal(&env)
	if _, err := Decode(tampered); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("tampered state want ErrChecksumMismatch, got %v", err)
	}
	// 截断 checksum 字段同样应失败（而不是默默接受）。
	env.Checksum = strings.Repeat("0", 64)
	forged, _ := json.Marshal(&env)
	if _, err := Decode(forged); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("forged checksum want ErrChecksumMismatch, got %v", err)
	}
}

func TestSaveLoadFileRoundTripAndAtomicArtifacts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snap.json")
	st := sampleState()
	if err := SaveToFile(path, st, "eng-1"); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.EngineID != "eng-1" {
		t.Fatalf("engine id mismatch: %s", got.EngineID)
	}
	// 反复/周期性导出不应留下临时文件垃圾。
	for i := 0; i < 10; i++ {
		if err := SaveToFile(path, st, "eng-1"); err != nil {
			t.Fatalf("resave %d: %v", i, err)
		}
	}
	fis, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, fi := range fis {
		if strings.HasPrefix(fi.Name(), ".snapshot-") {
			t.Fatalf("temporary snapshot file leaked: %s", fi.Name())
		}
	}
	// 目标文件权限符合预期且内容是单个 JSON 对象。
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("want 0600 perm, got %o", info.Mode().Perm())
	}
}

func TestCanonicalIsStableAcrossMapOrder(t *testing.T) {
	a := sampleState()
	b := sampleState()
	b.IngestSeen = map[string]string{"k2": "v2", "k1": "v1", "k3": "v3"}
	a.IngestSeen = map[string]string{"k3": "v3", "k1": "v1", "k2": "v2"}
	ca, _ := Canonical(a)
	cb, _ := Canonical(b)
	if string(ca) != string(cb) {
		t.Fatal("canonical encoding must be independent of map insertion order")
	}
}

// TestDecodeRejectsMissingOrInvalidTimePolicy 时间口径缺失/非法必须在
// 解码阶段被明确拒绝，且与版本不兼容、校验和损坏三类错误可区分。
func TestDecodeRejectsMissingOrInvalidTimePolicy(t *testing.T) {
	// 缺失节：重算校验和，确保不是以 checksum 失败的形式报出。
	strip := func() []byte {
		data, _ := Encode(sampleState(), "eng-1")
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatal(err)
		}
		env.State.TimePolicy = nil
		b, err := Canonical(env.State)
		if err != nil {
			t.Fatal(err)
		}
		sumArr := sha256.Sum256(b)
		env.Checksum = hex.EncodeToString(sumArr[:])
		out, _ := json.Marshal(&env)
		return out
	}
	if _, err := Decode(strip()); !errors.Is(err, ErrMissingTimePolicy) {
		t.Fatalf("缺失 time_policy 应报 ErrMissingTimePolicy, got %v", err)
	}
	// ValidateTimePolicy 直接调用：nil / 负数各自的分类。
	if err := ValidateTimePolicy(nil); !errors.Is(err, ErrMissingTimePolicy) {
		t.Fatalf("nil policy: got %v", err)
	}
	if err := ValidateTimePolicy(&TimePolicyState{MaxFutureSkew: -1}); !errors.Is(err, ErrInvalidTimePolicy) {
		t.Fatalf("负 skew: got %v", err)
	}
	if err := ValidateTimePolicy(&TimePolicyState{MaxFutureSkew: 1, MinAge: -1}); !errors.Is(err, ErrInvalidTimePolicy) {
		t.Fatalf("负 min_age: got %v", err)
	}
	// 合法口径（含零值 MinAge，零表示不限制、属于显式合法值）必须放行。
	if err := ValidateTimePolicy(&TimePolicyState{MaxFutureSkew: 0, MinAge: 0}); err != nil {
		t.Fatalf("零值口径应视为合法显式配置, got %v", err)
	}
}
