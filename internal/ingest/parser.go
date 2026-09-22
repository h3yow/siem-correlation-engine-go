// Package ingest 负责多种本地日志格式的解析、时间戳处理与归一化摄取。
package ingest

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Parser 把一条原始记录解析为字段映射。
type Parser interface {
	// Format 返回格式标识（json / syslog / keyvalue）。
	Format() string
	// Parse 仅做结构解析，不做时间戳/必填字段校验。
	// 结构性错误返回错误，由上层映射为 ReasonMalformed / ReasonUnsupportedFormat。
	Parse(raw string) (map[string]string, error)
}

var parsers = map[string]Parser{}

// RegisterParser 注册一个解析器。
func RegisterParser(p Parser) {
	if p != nil {
		parsers[p.Format()] = p
	}
}

func init() {
	RegisterParser(JSONParser{})
	RegisterParser(SyslogParser{})
	RegisterParser(KVParser{})
}

// JSONParser 解析单行 JSON 日志。
// 标量字段转为字符串；嵌套对象/数组序列化为 JSON 字符串保留在 Attributes 中。
type JSONParser struct{}

func (p JSONParser) Format() string { return "json" }

func (p JSONParser) Parse(raw string) (map[string]string, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		s, err := scalarToString(v)
		if err != nil {
			return nil, err
		}
		out[k] = s
	}
	return out, nil
}

func scalarToString(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "", nil
	case string:
		return t, nil
	case bool:
		return strconv.FormatBool(t), nil
	case json.Number:
		return t.String(), nil
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

// SyslogParser 解析 "TIMESTAMP HOST APP[PID]: MESSAGE" 形式的本地 syslog，
// MESSAGE 内部支持 key=value 片段（如 sshd 的 Failed password 消息另行归一）。
type SyslogParser struct{}

func (p SyslogParser) Format() string { return "syslog" }

func (p SyslogParser) Parse(raw string) (map[string]string, error) {
	// 预期形如：2026-09-23T10:00:01Z host01 sshd[1234]: message...
	// 或：      Sep 23 10:00:01 host01 sshd[1234]: message
	sp := strings.IndexByte(raw, ' ')
	if sp < 0 {
		return nil, errors.New("syslog: missing fields")
	}
	rest := raw
	fields := map[string]string{}

	// 尝试识别时间戳前缀：要么是 RFC3339 单 token，要么是 "Mmm d HH:MM:SS" 三 token。
	if ts, n, ok := consumeSyslogTimestamp(rest); ok {
		fields["timestamp"] = ts
		rest = strings.TrimSpace(rest[n:])
	} else {
		return nil, errors.New("syslog: cannot locate timestamp prefix")
	}

	// host
	sp = strings.IndexByte(rest, ' ')
	if sp < 0 {
		return nil, errors.New("syslog: missing host")
	}
	fields["host"] = rest[:sp]
	rest = strings.TrimSpace(rest[sp:])

	// app[pid]: message
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return nil, errors.New("syslog: missing app/message separator")
	}
	head := strings.TrimSpace(rest[:colon])
	msg := strings.TrimSpace(rest[colon+1:])
	fields["message"] = msg
	if lb := strings.IndexByte(head, '['); lb >= 0 {
		fields["app"] = head[:lb]
		pid := head[lb+1:]
		pid = strings.TrimSuffix(pid, "]")
		fields["pid"] = pid
	} else {
		fields["app"] = head
	}
	fields["source"] = fields["app"]

	// 从 message 中抽取内嵌 k=v
	for k, v := range parseKVPairs(msg) {
		if _, exists := fields[k]; !exists {
			fields[k] = v
		}
	}
	return fields, nil
}

// consumeSyslogTimestamp 返回时间戳原文、占用字节数。
func consumeSyslogTimestamp(s string) (string, int, bool) {
	// RFC3339：取到第一个空格
	if sp := strings.IndexByte(s, ' '); sp > 0 {
		tok := s[:sp]
		if strings.Contains(tok, "T") || strings.Contains(tok, "+") {
			return tok, sp, true
		}
	}
	// 传统 syslog：3 个 token
	parts := strings.SplitN(s, " ", 4)
	if len(parts) == 4 {
		ts := parts[0] + " " + parts[1] + " " + parts[2]
		return ts, len(ts), true
	}
	return "", 0, false
}

// KVParser 解析空格分隔的 key=value 日志（值可用双引号包裹）。
type KVParser struct{}

func (p KVParser) Format() string { return "keyvalue" }

func (p KVParser) Parse(raw string) (map[string]string, error) {
	if !strings.Contains(raw, "=") {
		return nil, errors.New("keyvalue: no key=value token")
	}
	m := parseKVPairs(raw)
	if len(m) == 0 {
		return nil, errors.New("keyvalue: no parsable pairs")
	}
	return m, nil
}

// parseKVPairs 从字符串中提取 key=value 片段；支持引号值与转义。
func parseKVPairs(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		// 定位 key
		for i < len(s) && s[i] == ' ' {
			i++
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= len(s) || s[i] != '=' {
			break
		}
		key := s[start:i]
		i++ // 跳过 '='
		var val string
		if i < len(s) && s[i] == '"' {
			i++
			var sb strings.Builder
			for i < len(s) {
				c := s[i]
				if c == '\\' && i+1 < len(s) {
					sb.WriteByte(s[i+1])
					i += 2
					continue
				}
				if c == '"' {
					i++
					break
				}
				sb.WriteByte(c)
				i++
			}
			val = sb.String()
		} else {
			vs := i
			for i < len(s) && s[i] != ' ' {
				i++
			}
			val = s[vs:i]
		}
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// DetectFormat 根据内容启发式判断格式；无法识别返回 ""。
func DetectFormat(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "{") {
		return "json"
	}
	if strings.Contains(trimmed, "=") {
		// 形如 key=value 起始才算 KV，避免把普通消息误判。
		first := strings.Fields(trimmed)
		if len(first) > 0 && strings.Contains(first[0], "=") {
			return "keyvalue"
		}
	}
	// syslog 兜底：存在冒号分隔且有时间戳特征。
	if _, _, ok := consumeSyslogTimestamp(trimmed); ok && strings.Contains(trimmed, ": ") {
		return "syslog"
	}
	return ""
}
