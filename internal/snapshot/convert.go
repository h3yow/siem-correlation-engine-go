package snapshot

import (
	"sort"

	"github.com/h3yow/siem-correlation-engine-go/internal/correlate"
	"github.com/h3yow/siem-correlation-engine-go/internal/event"
	"github.com/h3yow/siem-correlation-engine-go/internal/ingest"
	"github.com/h3yow/siem-correlation-engine-go/internal/rule"
	"github.com/h3yow/siem-correlation-engine-go/internal/suppress"
)

// ---- event ----

func eventToDTO(ev event.Event) *eventDTO {
	var attrs map[string]string
	if len(ev.Attributes) > 0 {
		attrs = make(map[string]string, len(ev.Attributes))
		for k, v := range ev.Attributes {
			attrs[k] = v
		}
	}
	return &eventDTO{
		ID:         ev.ID,
		OccurredAt: ev.OccurredAt,
		Source:     ev.Source,
		EventType:  ev.EventType,
		SrcHost:    ev.SrcHost,
		DstHost:    ev.DstHost,
		SrcIP:      ev.SrcIP,
		DstIP:      ev.DstIP,
		User:       ev.User,
		Action:     ev.Action,
		Status:     ev.Status,
		Severity:   int(ev.Severity),
		Attributes: attrs,
		Raw:        ev.Raw,
		RawFormat:  ev.RawFormat,
	}
}

func eventsToDTO(evs []event.Event) []*eventDTO {
	if len(evs) == 0 {
		return nil
	}
	out := make([]*eventDTO, len(evs))
	for i := range evs {
		out[i] = eventToDTO(evs[i])
	}
	return out
}

func eventFromDTO(d *eventDTO) event.Event {
	ev := event.Event{
		ID:         d.ID,
		OccurredAt: d.OccurredAt,
		Source:     d.Source,
		EventType:  d.EventType,
		SrcHost:    d.SrcHost,
		DstHost:    d.DstHost,
		SrcIP:      d.SrcIP,
		DstIP:      d.DstIP,
		User:       d.User,
		Action:     d.Action,
		Status:     d.Status,
		Severity:   event.Severity(d.Severity),
		Raw:        d.Raw,
		RawFormat:  d.RawFormat,
	}
	if len(d.Attributes) > 0 {
		ev.Attributes = make(map[string]string, len(d.Attributes))
		for k, v := range d.Attributes {
			ev.Attributes[k] = v
		}
	}
	return ev
}

// ---- rule ----

func ruleToDTO(r rule.Rule) ruleDTO {
	d := ruleDTO{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Severity:    int(r.Severity),
		Pattern:     make([]matchDTO, len(r.Pattern)),
		Window:      duration(r.Window),
		MaxGap:      duration(r.MaxGap),
		GroupBy:     r.GroupBy,
	}
	for i, m := range r.Pattern {
		d.Pattern[i] = matchDTO{
			Source: m.Source, EventType: m.EventType, Action: m.Action,
			User: m.User, SrcIP: m.SrcIP, DstIP: m.DstIP,
		}
	}
	return d
}

func ruleFromDTO(d ruleDTO) rule.Rule {
	r := rule.Rule{
		ID:          d.ID,
		Name:        d.Name,
		Description: d.Description,
		Severity:    event.Severity(d.Severity),
		Pattern:     make([]rule.Match, len(d.Pattern)),
		Window:      d.Window.std(),
		MaxGap:      d.MaxGap.std(),
		GroupBy:     d.GroupBy,
	}
	for i, m := range d.Pattern {
		r.Pattern[i] = rule.Match{
			Source: m.Source, EventType: m.EventType, Action: m.Action,
			User: m.User, SrcIP: m.SrcIP, DstIP: m.DstIP,
		}
	}
	return r
}

// ---- engine state ----

func engineStateToDTO(st correlate.EngineState) engineDTO {
	d := engineDTO{
		Watermark:       st.Watermark,
		AllowedLateness: duration(st.AllowedLateness),
		Suppression: suppressionCfgDTO{
			AggregateBy:    append([]string{}, st.Suppression.AggregateBy...),
			QuietFor:       duration(st.Suppression.QuietFor),
			MaxOccurrences: st.Suppression.MaxOccurrences,
		},
		RuleOrder: append([]string{}, st.RuleOrder...),
		Rules:     make([]detectorDTO, 0, len(st.Rules)),
		Pending:   eventsToDTO(st.Pending),
	}
	for _, b := range st.Suppress.Buckets {
		d.Buckets = append(d.Buckets, bucketDTO{
			AggregateKey:   b.AggregateKey,
			OpenedAt:       b.OpenedAt,
			QuietUntil:     b.QuietUntil,
			FirstAlertKey:  b.FirstAlertKey,
			OccurrenceCnt:  b.OccurrenceCnt,
			SampleEventIDs: append([]string{}, b.SampleEventIDs...),
		})
	}
	for _, ds := range st.Rules {
		fired := append([]string{}, ds.Fired...)
		sort.Strings(fired) // map 来源，排序保证重复导出字节确定
		rd := detectorDTO{
			Rule:    ruleToDTO(ds.Rule),
			Version: ds.Version,
			Fired:   fired,
			Groups:  make([]windowGroupDTO, 0, len(ds.Groups)),
		}
		groups := append([]correlate.WindowGroupState{}, ds.Groups...)
		sort.Slice(groups, func(i, j int) bool { return groups[i].Key < groups[j].Key })
		for _, g := range groups {
			rd.Groups = append(rd.Groups, windowGroupDTO{Key: g.Key, Events: eventsToDTO(g.Events)})
		}
		d.Rules = append(d.Rules, rd)
	}
	return d
}

func engineStateFromDTO(d engineDTO) correlate.EngineState {
	st := correlate.EngineState{
		Watermark:       d.Watermark,
		AllowedLateness: d.AllowedLateness.std(),
		Suppression: rule.SuppressionConfig{
			AggregateBy:    append([]string{}, d.Suppression.AggregateBy...),
			QuietFor:       d.Suppression.QuietFor.std(),
			MaxOccurrences: d.Suppression.MaxOccurrences,
		},
		RuleOrder: append([]string{}, d.RuleOrder...),
		Rules:     make([]correlate.DetectorState, 0, len(d.Rules)),
		Pending:   make([]event.Event, 0, len(d.Pending)),
	}
	for _, b := range d.Buckets {
		st.Suppress.Buckets = append(st.Suppress.Buckets, suppress.Bucket{
			AggregateKey:   b.AggregateKey,
			OpenedAt:       b.OpenedAt,
			QuietUntil:     b.QuietUntil,
			FirstAlertKey:  b.FirstAlertKey,
			OccurrenceCnt:  b.OccurrenceCnt,
			SampleEventIDs: append([]string{}, b.SampleEventIDs...),
		})
	}
	st.Suppress.QuietFor = st.Suppression.QuietFor
	st.Suppress.MaxOccurrences = st.Suppression.MaxOccurrences
	for _, rd := range d.Rules {
		ds := correlate.DetectorState{
			Rule:    ruleFromDTO(rd.Rule),
			Version: rd.Version,
			Fired:   append([]string{}, rd.Fired...),
			Groups:  make([]correlate.WindowGroupState, 0, len(rd.Groups)),
		}
		for _, g := range rd.Groups {
			gs := correlate.WindowGroupState{Key: g.Key, Events: make([]event.Event, 0, len(g.Events))}
			for _, ed := range g.Events {
				gs.Events = append(gs.Events, eventFromDTO(ed))
			}
			ds.Groups = append(ds.Groups, gs)
		}
		st.Rules = append(st.Rules, ds)
	}
	for _, ed := range d.Pending {
		st.Pending = append(st.Pending, eventFromDTO(ed))
	}
	return st
}

// ---- ingest state ----

func ingestStateToDTO(st ingest.State, cfg ingestConfigDTO) ingestDTO {
	seen := make(map[string]string, len(st.Seen))
	for k, v := range st.Seen {
		seen[k] = v
	}
	return ingestDTO{Config: cfg, Seen: seen, DupCount: st.DupCount}
}

func ingestStateFromDTO(d ingestDTO) ingest.State {
	seen := make(map[string]string, len(d.Seen))
	for k, v := range d.Seen {
		seen[k] = v
	}
	return ingest.State{Seen: seen, DupCount: d.DupCount}
}
