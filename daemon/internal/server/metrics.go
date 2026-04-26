package server

import (
	"sync"

	"github.com/cordum-io/cordclaw/daemon/internal/redact"
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
