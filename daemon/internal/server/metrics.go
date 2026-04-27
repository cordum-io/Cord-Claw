package server

import (
	"sync"

	"github.com/cordum-io/cordclaw/daemon/internal/redact"
	"github.com/prometheus/client_golang/prometheus"
)

type dlpMetrics struct {
	mu        sync.Mutex
	decisions map[string]int
	matches   map[string]int
}

func newDLPMetrics() *dlpMetrics {
	return &dlpMetrics{
		decisions: make(map[string]int),
		matches:   make(map[string]int),
	}
}

func (m *dlpMetrics) recordDecision(action string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[action]++
}

func (m *dlpMetrics) recordMatches(matches []redact.Match) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, match := range matches {
		m.matches[match.Name]++
	}
}

func newShadowEventsCounter(reg prometheus.Registerer) prometheus.Counter {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cordclaw_shadow_events_total",
		Help: "Total number of CordClaw shadow-mode rule matches emitted to the shadow-event callback.",
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
	return counter
}
