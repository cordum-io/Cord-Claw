// Package ratelimit provides CordClaw's daemon-local emission throttle.
//
// The limiter is keyed by OpenClaw agent id. It uses a per-agent token
// bucket with burst=int(rps), so the default 50/s setting allows an
// initial 50-call burst and refills at 50 calls per second. Agent entries
// are retained for one hour after last use and can be evicted with GC.
package ratelimit

import (
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
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
	limiter          *rate.Limiter
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
			slog.Info("cordclaw rate limited", "agent_id", agentID, "count", count)
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
	defer func() {
		if recovered := recover(); recovered != nil {
			allowed = false
		}
	}()
	if e == nil {
		return false
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
			limiter:  rate.NewLimiter(rate.Limit(e.rps), e.burst),
			lastSeen: now,
		}
		e.limiters[agentID] = ent
	}
	ent.lastSeen = now
	if ent.limiter.AllowN(now, 1) {
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
