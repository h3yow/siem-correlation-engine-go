package parser

import (
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
)

// Validator 对解析后的事件做归一化校验：时间戳不得过远未来或过旧。
type Validator struct {
	MaxFutureSkew time.Duration
	MaxAge        time.Duration
}

func NewValidator(maxFutureSkewSec, maxAgeSec int64) *Validator {
	return &Validator{
		MaxFutureSkew: time.Duration(maxFutureSkewSec) * time.Second,
		MaxAge:        time.Duration(maxAgeSec) * time.Second,
	}
}

func (v *Validator) Validate(ev *event.Event, now time.Time) error {
	if ev.Timestamp.IsZero() {
		return Errf(event.RejectMissingTime, "event %s has zero timestamp", ev.ID)
	}
	if !ev.Timestamp.Before(now.Add(v.MaxFutureSkew)) {
		return Errf(event.RejectFutureTime, "event %s timestamp %s is beyond now+%s",
			ev.ID, ev.Timestamp.Format(time.RFC3339), v.MaxFutureSkew)
	}
	if v.MaxAge > 0 && ev.Timestamp.Before(now.Add(-v.MaxAge)) {
		return Errf(event.RejectTooOld, "event %s timestamp %s is older than max age %s",
			ev.ID, ev.Timestamp.Format(time.RFC3339), v.MaxAge)
	}
	return nil
}
