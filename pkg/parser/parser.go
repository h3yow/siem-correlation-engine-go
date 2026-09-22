package parser

import (
	"fmt"
	"strings"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// ParseError 携带可区分的拒绝原因。
type ParseError struct {
	Reason event.RejectReason
	Detail string
}

func (e *ParseError) Error() string { return string(e.Reason) + ": " + e.Detail }

// Errf 构造解析错误。
func Errf(reason event.RejectReason, format string, args ...any) *ParseError {
	return &ParseError{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// Parser 把某种本地日志格式解析为归一化事件。
type Parser interface {
	Name() string
	Parse(line, source string) (*event.Event, error)
}

// Registry 管理多种格式解析器。
type Registry struct {
	parsers map[string]Parser
}

func NewRegistry() *Registry { return &Registry{parsers: map[string]Parser{}} }

func (r *Registry) Register(p Parser) { r.parsers[p.Name()] = p }

func (r *Registry) Get(name string) (Parser, bool) {
	p, ok := r.parsers[name]
	return p, ok
}

// ParseAuto 依据行内容猜测格式并解析；无法识别时返回 unsupported_format。
func (r *Registry) ParseAuto(line, source string) (*event.Event, string, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, "", Errf(event.RejectEmpty, "record is empty")
	}
	var name string
	switch {
	case strings.HasPrefix(trimmed, "{"):
		name = "json"
	case strings.Contains(trimmed, "="):
		name = "kv"
	case strings.Contains(trimmed, ","):
		name = "csv"
	default:
		return nil, "", Errf(event.RejectUnsupportedFmt, "cannot detect format of record")
	}
	p, ok := r.parsers[name]
	if !ok {
		return nil, name, Errf(event.RejectUnsupportedFmt, "no parser registered for format %q", name)
	}
	ev, err := p.Parse(trimmed, source)
	if err != nil {
		return nil, name, err
	}
	return ev, name, nil
}
