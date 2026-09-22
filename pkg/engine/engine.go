package engine

import (
	"fmt"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/h3yow/siem-correlation-engine-go/pkg/alert"
	"github.com/h3yow/siem-correlation-engine-go/pkg/event"
	"github.com/h3yow/siem-correlation-engine-go/pkg/parser"
	"github.com/h3yow/siem-correlation-engine-go/pkg/rule"
	"github.com/h3yow/siem-correlation-engine-go/pkg/suppression"
	"github.com/h3yow/siem-correlation-engine-go/pkg/window"
)

// Config 是引擎配置。
type Config struct {
	MaxFutureSkewSec int64
	MaxAgeSec        int64
	// HistoryLimit 是为规则热更新回放保留的最大历史事件数。
	HistoryLimit int
	// Logger 用于打印窗口状态与判定依据；nil 时不打印。
	Logger *log.Logger
	Now    func() time.Time
}

// Result 是一次摄取的结果。
type Result struct {
	Accepted []*event.Event
	Rejected []event.RejectedRecord
	Alerts   []*alert.Alert
}

type job struct {
	line    string
	source  string
	resultC chan Result
}

// Engine 串起解析校验、窗口关联、抑制与规则热更新。
// 摄取通过 procMu 串行化，保证乱序/并发下结论一致且可复现。
type Engine struct {
	cfg       Config
	now       func() time.Time
	regs      *parser.Registry
	rules     *rule.Store
	windows   *window.Manager
	suppress  map[string]*suppression.Suppressor
	validator *parser.Validator
	logger    *log.Logger

	seq      int64
	procMu   sync.Mutex
	mu       sync.Mutex
	history  []*event.Event
	seenIDs  map[string]struct{}
	allAlert []*alert.Alert

	jobs    chan job
	stopCh  chan struct{}
	wg      sync.WaitGroup
	started bool
}

func New(cfg Config) *Engine {
	if cfg.HistoryLimit <= 0 {
		cfg.HistoryLimit = 10000
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{
		cfg:       cfg,
		now:       cfg.Now,
		regs:      parser.NewRegistry(),
		rules:     rule.NewStore(),
		windows:   window.NewManager(),
		suppress:  map[string]*suppression.Suppressor{},
		validator: parser.NewValidator(cfg.MaxFutureSkewSec, cfg.MaxAgeSec),
		logger:    cfg.Logger,
		seenIDs:   map[string]struct{}{},
		jobs:      make(chan job, 1024),
		stopCh:    make(chan struct{}),
	}
}

func (e *Engine) Registry() *parser.Registry { return e.regs }
func (e *Engine) Rules() *rule.Store         { return e.rules }

// Start 启动后台串行摄取循环。
func (e *Engine) Start() {
	e.procMu.Lock()
	if e.started {
		e.procMu.Unlock()
		return
	}
	e.started = true
	e.procMu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			select {
			case j := <-e.jobs:
				j.resultC <- e.process(j.line, j.source)
			case <-e.stopCh:
				for {
					select {
					case j := <-e.jobs:
						j.resultC <- e.process(j.line, j.source)
					default:
						return
					}
				}
			}
		}
	}()
}

// Stop 停止后台循环并排空队列。
func (e *Engine) Stop() {
	e.procMu.Lock()
	if !e.started {
		e.procMu.Unlock()
		return
	}
	e.started = false
	e.procMu.Unlock()
	close(e.stopCh)
	e.wg.Wait()
}

// Ingest 投递一行原始日志；Start 后经后台 worker 串行处理，
// 未 Start 时自动退化为同步串行处理。调用方会等待结论。
func (e *Engine) Ingest(line, source string) {
	e.procMu.Lock()
	started := e.started
	e.procMu.Unlock()
	if !started {
		e.process(line, source)
		return
	}
	j := job{line: line, source: source, resultC: make(chan Result, 1)}
	e.jobs <- j
	<-j.resultC
}

// IngestSync 同步处理一行原始日志（Start 前/后均可调用，仍串行化）。
func (e *Engine) IngestSync(line, source string) Result {
	return e.process(line, source)
}

// process 是唯一的串行处理入口。
func (e *Engine) process(line, source string) Result {
	e.procMu.Lock()
	defer e.procMu.Unlock()

	res := Result{}
	now := e.now()
	ev, _, perr := e.regs.ParseAuto(line, source)
	if perr != nil {
		rec := rejected(perr, line, source)
		res.Rejected = append(res.Rejected, rec)
		e.logf("[reject] %s raw=%q", rec.Reason, truncate(line))
		return res
	}
	if verr := e.validator.Validate(ev, now); verr != nil {
		rec := rejected(verr, line, source)
		res.Rejected = append(res.Rejected, rec)
		e.logf("[reject] %s id=%s", rec.Reason, ev.ID)
		return res
	}

	e.mu.Lock()
	if _, dup := e.seenIDs[ev.ID]; dup {
		e.mu.Unlock()
		rec := event.RejectedRecord{
			Raw: line, Source: source,
			Reason: event.RejectDuplicateID,
			Detail: fmt.Sprintf("event id %s already ingested", ev.ID),
		}
		res.Rejected = append(res.Rejected, rec)
		e.logf("[reject] %s id=%s", rec.Reason, ev.ID)
		return res
	}
	e.seenIDs[ev.ID] = struct{}{}
	ev.IngestSeq = atomic.AddInt64(&e.seq, 1)
	e.history = append(e.history, ev)
	if len(e.history) > e.cfg.HistoryLimit {
		e.history = e.history[len(e.history)-e.cfg.HistoryLimit:]
	}
	e.mu.Unlock()
	res.Accepted = append(res.Accepted, ev)

	alerts, late := e.evaluate(ev, now)
	res.Alerts = alerts
	res.Rejected = append(res.Rejected, late...)
	e.mu.Lock()
	e.allAlert = append(e.allAlert, alerts...)
	e.mu.Unlock()
	return res
}

// evaluate 对全部启用规则评估单个新事件。
func (e *Engine) evaluate(ev *event.Event, now time.Time) ([]*alert.Alert, []event.RejectedRecord) {
	var out []*alert.Alert
	var lateRej []event.RejectedRecord
	for _, r := range e.rules.Snapshot() {
		if r.Disabled {
			continue
		}
		partition := r.PartitionKey(ev)
		wm := e.windows.WatermarkOf(r.ID, partition)
		ar := e.windows.Add(r, partition, ev, now)
		if ar.DroppedLate {
			rec := event.RejectedRecord{
				Raw: ev.Raw, Source: ev.Source,
				Reason: event.RejectLateDropped,
				Detail: fmt.Sprintf("event %s (ts=%s) 对规则 %s 晚于水位线 %s，拒绝参与关联",
					ev.ID, ev.Timestamp.Format(time.RFC3339), r.ID,
					wm.Format(time.RFC3339)),
			}
			lateRej = append(lateRej, rec)
			e.logf("[late] id=%s rule=%s ts=%s 晚于水位线，拒绝参与关联",
				ev.ID, r.ID, ev.Timestamp.Format(time.RFC3339))
			continue
		}
		e.logState(r, partition, ev)
		sup := e.suppressorFor(r)
		for _, mt := range ar.Matches {
			a := e.buildAlert(mt)
			sup.Apply(a, now)
			if a.Suppressed {
				e.logf("[suppress] fp=%s rule=%s count=%d 重复/高频告警已聚合",
					a.Fingerprint, r.ID, a.Count)
			} else {
				e.logf("[fire] fp=%s rule=%s v%d partition=%q events=%v window=[%s,%s] 原因=%s",
					a.Fingerprint, r.ID, r.Version, partition, a.EventIDs,
					mt.WindowStart.Format(time.RFC3339), mt.WindowEnd.Format(time.RFC3339), a.Reason)
			}
			out = append(out, a)
		}
	}
	return out, lateRej
}

func (e *Engine) suppressorFor(r *rule.Rule) *suppression.Suppressor {
	sup := e.suppress[r.ID]
	if sup == nil {
		sup = suppression.New(r.DedupWindow)
		e.suppress[r.ID] = sup
	}
	return sup
}

func (e *Engine) buildAlert(mt window.Match) *alert.Alert {
	ids := make([]string, len(mt.Events))
	for i, ev := range mt.Events {
		ids[i] = ev.ID
	}
	return &alert.Alert{
		ID:          "alert-" + mt.RuleID + "-" + ids[0],
		Fingerprint: alert.FingerprintFor(mt.RuleID, mt.Partition, mt.Events),
		RuleID:      mt.RuleID,
		RuleVersion: mt.RuleVersion,
		Partition:   mt.Partition,
		Severity:    alert.HighestSeverity(mt.Events),
		EventIDs:    ids,
		WindowStart: mt.WindowStart,
		WindowEnd:   mt.WindowEnd,
		FiredAt:     mt.MatchedAt,
		Reason:      explain(mt),
	}
}

// explain 给出人可读的判定依据。
func explain(mt window.Match) string {
	steps := make([]string, len(mt.Events))
	for i, ev := range mt.Events {
		steps[i] = fmt.Sprintf("%s(type=%s,ts=%s)", ev.ID, ev.Type, ev.Timestamp.Format(time.RFC3339))
	}
	return fmt.Sprintf("规则 %s 在事件时间窗 [%s, %s] 内按序匹配 %d 个步骤；证据链: %s",
		mt.RuleID, mt.WindowStart.Format(time.RFC3339), mt.WindowEnd.Format(time.RFC3339),
		len(mt.Events), joinSteps(steps))
}

func joinSteps(steps []string) string {
	out := ""
	for i, s := range steps {
		if i > 0 {
			out += " -> "
		}
		out += s
	}
	return out
}

func (e *Engine) logState(r *rule.Rule, partition string, ev *event.Event) {
	if e.logger == nil {
		return
	}
	for _, st := range e.windows.Snapshot(r.ID) {
		if st.Partition != partition {
			continue
		}
		ids := make([]string, len(st.Events))
		for i, x := range st.Events {
			ids[i] = x.ID
		}
		e.logf("[window] rule=%s partition=%q 窗口内事件数=%d 事件=%v maxTS=%s watermark=%s 当前事件=%s",
			r.ID, st.Partition, len(st.Events), ids,
			st.MaxTS.Format(time.RFC3339), st.Watermark.Format(time.RFC3339), ev.ID)
	}
}

// UpdateRule 运行期新增/更新规则。新规则对保留的历史事件按事件时间顺序
// 回放判定（已触发过的指纹不会重复告警）；既有规则保留已积累窗口状态。
func (e *Engine) UpdateRule(r *rule.Rule) (int64, error) {
	e.procMu.Lock()
	defer e.procMu.Unlock()
	if err := r.Validate(); err != nil {
		return 0, err
	}
	_, existed := e.rules.Get(r.ID)
	rev := e.rules.Upsert(r)
	if !existed {
		e.replayForNewRule(r)
	} else {
		e.logf("[rule-update] 规则 %s 更新为 v%d，保留既有窗口状态，不重复触发历史告警", r.ID, r.Version)
	}
	return rev, nil
}

func (e *Engine) replayForNewRule(r *rule.Rule) {
	e.mu.Lock()
	hist := append([]*event.Event(nil), e.history...)
	e.mu.Unlock()
	sort.Slice(hist, func(i, j int) bool {
		if !hist[i].Timestamp.Equal(hist[j].Timestamp) {
			return hist[i].Timestamp.Before(hist[j].Timestamp)
		}
		return hist[i].IngestSeq < hist[j].IngestSeq
	})
	now := e.now()
	sup := e.suppressorFor(r)
	var produced []*alert.Alert
	for _, ev := range hist {
		partition := r.PartitionKey(ev)
		ar := e.windows.Add(r, partition, ev, now)
		if ar.DroppedLate {
			continue
		}
		for _, mt := range ar.Matches {
			a := e.buildAlert(mt)
			sup.Apply(a, now)
			produced = append(produced, a)
			if a.Suppressed {
				e.logf("[replay-suppress] rule=%s fp=%s count=%d", r.ID, a.Fingerprint, a.Count)
			} else {
				e.logf("[replay-fire] rule=%s v%d events=%v 原因=%s",
					r.ID, a.RuleVersion, a.EventIDs, a.Reason)
			}
		}
	}
	if len(produced) > 0 {
		e.mu.Lock()
		e.allAlert = append(e.allAlert, produced...)
		e.mu.Unlock()
	}
	e.logf("[rule-update] 新规则 %s v%d 已回放 %d 个历史事件，产生 %d 条告警（含抑制）",
		r.ID, r.Version, len(hist), len(produced))
}

// DeleteRule 在运行期删除规则并清理其窗口状态。
// 抑制聚合状态按 ruleID 保留：同一规则被重新加入并回放历史时，
// 已产生过的告警指纹会被抑制，不会重复触发。
func (e *Engine) DeleteRule(id string) bool {
	e.procMu.Lock()
	defer e.procMu.Unlock()
	if !e.rules.Delete(id) {
		return false
	}
	e.windows.DropRule(id)
	return true
}

// Alerts 返回已产生告警（含被抑制）的副本快照。
func (e *Engine) Alerts() []*alert.Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*alert.Alert, len(e.allAlert))
	copy(out, e.allAlert)
	return out
}

// Housekeep 推进水位线淘汰空闲窗口与过期抑制状态。
func (e *Engine) Housekeep() (windows, sups int) {
	e.procMu.Lock()
	defer e.procMu.Unlock()
	now := e.now()
	ev := e.windows.AdvanceWatermark(e.rules.Snapshot(), now)
	for id, sup := range e.suppress {
		if n := sup.Evict(now); n > 0 {
			sups += n
		}
		_ = id
	}
	return len(ev), sups
}

func rejected(err error, line, source string) event.RejectedRecord {
	reason := event.RejectMalformed
	var pe *parser.ParseError
	if ok := asParseError(err, &pe); ok {
		reason = pe.Reason
	}
	return event.RejectedRecord{Raw: line, Source: source, Reason: reason, Detail: err.Error()}
}

func asParseError(err error, target **parser.ParseError) bool {
	for err != nil {
		if pe, ok := err.(*parser.ParseError); ok {
			*target = pe
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func (e *Engine) logf(format string, args ...any) {
	if e.logger != nil {
		e.logger.Printf(format, args...)
	}
}

func truncate(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}
