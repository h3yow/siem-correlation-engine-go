package parser

import (
	"encoding/csv"
	"strconv"
	"strings"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// CSVParser 解析固定列 CSV：id,ts,type,severity,subject,message
// ts 支持 RFC3339 字符串或 unix 秒。
type CSVParser struct{}

func NewCSVParser() *CSVParser    { return &CSVParser{} }
func (p *CSVParser) Name() string { return "csv" }

func (p *CSVParser) Parse(line, source string) (*event.Event, error) {
	rec, err := csv.NewReader(strings.NewReader(line)).Read()
	if err != nil {
		return nil, Errf(event.RejectMalformed, "invalid csv: %v", err)
	}
	if len(rec) < 6 {
		return nil, Errf(event.RejectMalformed, "csv expects 6 columns id,ts,type,severity,subject,message, got %d", len(rec))
	}
	for i := range rec {
		rec[i] = strings.TrimSpace(rec[i])
	}
	if rec[0] == "" {
		return nil, Errf(event.RejectMissingID, "csv record missing id")
	}
	if rec[2] == "" {
		return nil, Errf(event.RejectMissingType, "csv record missing type")
	}
	if rec[1] == "" {
		return nil, Errf(event.RejectMissingTime, "csv record missing ts")
	}
	var ts time.Time
	if t, err := time.Parse(time.RFC3339Nano, rec[1]); err == nil {
		ts = t.UTC()
	} else if t, err := time.Parse("2006-01-02 15:04:05", rec[1]); err == nil {
		ts = t.UTC()
	} else if sec, err := strconv.ParseInt(rec[1], 10, 64); err == nil && sec > 0 {
		ts = time.Unix(sec, 0).UTC()
	} else {
		return nil, Errf(event.RejectBadTimestamp, "unparseable csv timestamp %q", rec[1])
	}
	return &event.Event{
		ID:        rec[0],
		Source:    source,
		Type:      rec[2],
		Timestamp: ts,
		Severity:  NormalizeSeverity(rec[3]),
		Subject:   rec[4],
		Message:   rec[5],
		Raw:       line,
		Attrs:     map[string]string{},
	}, nil
}
