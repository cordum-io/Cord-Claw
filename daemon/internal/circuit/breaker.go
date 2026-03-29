package circuit

import (
	"sync"
	"time"
)

type State string

const (
	StateClosed   State = "closed"
	StateOpen     State = "open"
	StateHalfOpen State = "half-open"
)

type Config struct {
	FailThreshold       int
	OpenDuration        time.Duration
	HalfOpenMaxProbes   int
	CloseAfterSuccesses int
}

type Breaker struct {
	mu sync.Mutex

	cfg Config

	state State

	consecutiveFailures  int
	consecutiveSuccesses int
	halfOpenProbeCount   int
	openedAt             time.Time
}

func DefaultConfig() Config {
	return Config{
		FailThreshold:       3,
		OpenDuration:        30 * time.Second,
		HalfOpenMaxProbes:   3,
		CloseAfterSuccesses: 2,
	}
}

func New(cfg Config) *Breaker {
	if cfg.FailThreshold <= 0 {
		cfg.FailThreshold = 3
	}
	if cfg.OpenDuration <= 0 {
		cfg.OpenDuration = 30 * time.Second
	}
	if cfg.HalfOpenMaxProbes <= 0 {
		cfg.HalfOpenMaxProbes = 3
	}
	if cfg.CloseAfterSuccesses <= 0 {
		cfg.CloseAfterSuccesses = 2
	}
	return &Breaker{cfg: cfg, state: StateClosed}
}

func (b *Breaker) State(now time.Time) State {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked(now)
	return b.state
}

func (b *Breaker) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked(now)
	switch b.state {
	case StateClosed:
		return true
	case StateOpen:
		return false
	case StateHalfOpen:
		if b.halfOpenProbeCount >= b.cfg.HalfOpenMaxProbes {
			return false
		}
		b.halfOpenProbeCount++
		return true
	default:
		return false
	}
}

func (b *Breaker) OnSuccess(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked(now)
	switch b.state {
	case StateClosed:
		b.consecutiveFailures = 0
	case StateHalfOpen:
		b.consecutiveSuccesses++
		if b.consecutiveSuccesses >= b.cfg.CloseAfterSuccesses {
			b.resetToClosedLocked()
		}
	}
}

func (b *Breaker) OnFailure(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advanceLocked(now)
	switch b.state {
	case StateClosed:
		b.consecutiveFailures++
		if b.consecutiveFailures >= b.cfg.FailThreshold {
			b.tripOpenLocked(now)
		}
	case StateHalfOpen:
		b.tripOpenLocked(now)
	}
}

func (b *Breaker) advanceLocked(now time.Time) {
	if b.state == StateOpen && now.Sub(b.openedAt) >= b.cfg.OpenDuration {
		b.state = StateHalfOpen
		b.consecutiveSuccesses = 0
		b.halfOpenProbeCount = 0
	}
}

func (b *Breaker) tripOpenLocked(now time.Time) {
	b.state = StateOpen
	b.openedAt = now
	b.consecutiveFailures = 0
	b.consecutiveSuccesses = 0
	b.halfOpenProbeCount = 0
}

func (b *Breaker) resetToClosedLocked() {
	b.state = StateClosed
	b.consecutiveFailures = 0
	b.consecutiveSuccesses = 0
	b.halfOpenProbeCount = 0
	b.openedAt = time.Time{}
}
