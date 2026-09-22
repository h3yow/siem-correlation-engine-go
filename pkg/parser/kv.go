package parser

import (
	"strconv"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// KVParser 解析空格分隔的 key=value 行，值可用双引号包裹。
// 保留键：id, ts, type, severity, subject, msg；其余键进入 Attrs。
type KVParser struct{}

func NewKVParser() *KVParser     { return &KVParser{} }
func (p *KVParser) Name() string { return "kv" }

func (p *KVParser) Parse(line, source string) (*event.Event, error) {
	fields, err := splitKV(line)
	if err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, Errf(event.RejectMalformed, "no key=value pairs found")
	}
	ev := &event.Event{Source: source, Raw: line, Attrs: map[string]string{}}
	var tsStr string
	for k, v := range fields {
		switch k {
		case "id":
			ev.ID = v
		case "ts":
			tsStr = v
		case "type":
			ev.Type = v
		case "severity":
			ev.Severity = NormalizeSeverity(v)
		case "subject":
			ev.Subject = v
		case "msg":
			ev.Message = v
		default:
			ev.Attrs[k] = v
		}
	}
	if ev.ID == "" {
		return nil, Errf(event.RejectMissingID, "kv record missing id")
	}
	if ev.Type == "" {
		return nil, Errf(event.RejectMissingType, "kv record missing type")
	}
	if tsStr == "" {
		return nil, Errf(event.RejectMissingTime, "kv record missing ts")
	}
	ts, err := parseKVTime(tsStr)
	if err != nil {
		return nil, err
	}
	ev.Timestamp = ts
	return ev, nil
}

// splitKV 按空白切分，支持 "quoted value"。
func splitKV(line string) (map[string]string, error) {
	out := map[string]string{}
	i := 0
	n := len(line)
	for i < n {
		for i < n && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && line[i] != '=' && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		key := line[start:i]
		if i >= n || line[i] != '=' {
			return nil, Errf(event.RejectMalformed, "token %q is not key=value", key)
		}
		i++ // skip '='
		var val string
		if i < n && line[i] == '"' {
			i++
			end := strings.IndexByte(line[i:], '"')
			if end < 0 {
				return nil, Errf(event.RejectMalformed, "unterminated quoted value for key %q", key)
			}
			val = line[i : i+end]
			i += end + 1
		} else {
			start = i
			for i < n && line[i] != ' ' && line[i] != '\t' {
				i++
			}
			val = line[start:i]
		}
		out[key] = val
	}
	return out, nil
}

func parseKVTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC(), nil
	}
	if sec, err := strconv.ParseInt(s, 10, 64); err == nil && sec > 0 {
		return time.Unix(sec, 0).UTC(), nil
	}
	return time.Time{}, Errf(event.RejectBadTimestamp, "unparseable timestamp %q", s)
}
