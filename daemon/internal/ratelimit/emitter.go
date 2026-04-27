// Package ratelimit provides CordClaw's daemon-local emission throttle.
//
// The limiter is keyed by OpenClaw agent id. It uses a per-agent rolling
// one-second window with capacity=int(rps), so the default 50/s setting
// allows at most 50 calls in any one-second interval. Agent entries are
// retained for one hour after last use and can be evicted with GC.
package ratelimit

import (
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const agentEntryTTL = time.Hour

// Emitter enforces a per-agent emission rate limit.
type Emitter struct {
	mu                sync.Mutex
	limiters          map[string]*agentEntry
	rps               float64
	burst             int
	now               func() time.Time
	onSummary         func(agentID string, count int)
	metricRateLimited prometheus.Counter
	closed            bool
}

type agentEntry struct {
	rps              float64
	burst            int
	events           []time.Time
	lastSeen         time.Time
	pendingDenials   int
	summaryScheduled bool
	summaryTimer     *time.Timer
}

// New creates a per-agent rate-limit emitter.
func New(rps float64, onSummary func(string, int), reg prometheus.Registerer) *Emitter {
	if rps < 1 || math.IsNaN(rps) || math.IsInf(rps, 0) {
		panic("cordclaw rate limit rps must be >= 1")
	}
	if onSummary == nil {
		onSummary = func(agentID string, count int) {
			slog.Info("cordclaw rate limited", "agent_id", agentID, "denied_count", count)
		}
	}
	// Intentionally unlabeled: agent_id labels are unbounded cardinality.
	// Follow-up task-ad5dbc61 evaluates bounded per-agent telemetry.
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cordclaw_rate_limited_total",
		Help: "Total number of CordClaw emissions denied by the per-agent rate limiter.",
	})
	if reg != nil {
		if err := reg.Register(counter); err != nil {
			if already, ok := err.(prometheus.AlreadyRegisteredError); ok {
				if existing, ok := already.ExistingCollector.(prometheus.Counter); ok {
					counter = existing
				}
			}
		}
	}
	return &Emitter{
		limiters:          make(map[string]*agentEntry),
		rps:               rps,
		burst:             int(rps),
		now:               time.Now,
		onSummary:         onSummary,
		metricRateLimited: counter,
	}
}

// Allow reports whether agentID may emit another action now. It fails
// closed on internal panics.
func (e *Emitter) Allow(agentID string) (allowed bool) {
	return e.AllowWithLimit(agentID, e.rps)
}

// AllowWithLimit reports whether agentID may emit another action using an
// agent-specific rate limit. It fails closed on internal panics.
func (e *Emitter) AllowWithLimit(agentID string, rps float64) (allowed bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			allowed = false
		}
	}()
	if e == nil {
		return false
	}
	if rps < 1 || math.IsNaN(rps) || math.IsInf(rps, 0) {
		rps = e.rps
	}
	burst := int(rps)
	if burst < 1 {
		burst = 1
	}
	agentID = normalizeAgentID(agentID)
	now := e.now()

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return false
	}
	ent := e.limiters[agentID]
	if ent == nil {
		ent = &agentEntry{
			rps:      rps,
			burst:    burst,
			events:   make([]time.Time, 0, burst),
			lastSeen: now,
		}
		e.limiters[agentID] = ent
	} else if ent.rps != rps || ent.burst != burst {
		ent.rps = rps
		ent.burst = burst
		if cap(ent.events) < burst {
			events := make([]time.Time, len(ent.events), burst)
			copy(events, ent.events)
			ent.events = events
		}
	}
	ent.lastSeen = now
	ent.events = pruneEvents(ent.events, now.Add(-time.Second))
	if len(ent.events) < ent.burst {
		ent.events = append(ent.events, now)
		return true
	}

	ent.pendingDenials++
	e.metricRateLimited.Inc()
	if !ent.summaryScheduled {
		ent.summaryScheduled = true
		delay := time.Until(endOfCurrentSecond(now))
		if delay < 0 {
			delay = 0
		}
		ent.summaryTimer = time.AfterFunc(delay, func() {
			e.flushSummary(agentID)
		})
	}
	return false
}

// GC evicts agent entries that have been inactive for more than one hour.
func (e *Emitter) GC() {
	if e == nil {
		return
	}
	now := e.now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for agentID, ent := range e.limiters {
		if now.Sub(ent.lastSeen) <= agentEntryTTL {
			continue
		}
		if ent.summaryTimer != nil {
			ent.summaryTimer.Stop()
		}
		delete(e.limiters, agentID)
	}
}

// Close stops all pending summary timers. It is safe to call more than once.
func (e *Emitter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	for _, ent := range e.limiters {
		if ent.summaryTimer != nil {
			ent.summaryTimer.Stop()
		}
	}
}

func (e *Emitter) flushSummary(agentID string) {
	if e == nil {
		return
	}
	var count int
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	ent := e.limiters[agentID]
	if ent != nil {
		count = ent.pendingDenials
		ent.pendingDenials = 0
		ent.summaryScheduled = false
		ent.summaryTimer = nil
	}
	e.mu.Unlock()

	if count <= 0 {
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Warn("cordclaw rate-limit summary callback panicked", "agent_id", agentID)
		}
	}()
	e.onSummary(agentID, count)
}

func normalizeAgentID(agentID string) string {
	agentID = strings.TrimSpace(agentID)
	if agentID == "" {
		return "unknown"
	}
	return agentID
}

func endOfCurrentSecond(now time.Time) time.Time {
	return now.Truncate(time.Second).Add(time.Second)
}

func pruneEvents(events []time.Time, cutoff time.Time) []time.Time {
	first := 0
	for first < len(events) && !events[first].After(cutoff) {
		first++
	}
	if first == 0 {
		return events
	}
	if first == len(events) {
		return events[:0]
	}
	copy(events, events[first:])
	return events[:len(events)-first]
}
