package circuit

import (
	"testing"
	"time"
)

func TestBreakerTransitions(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OpenDuration = 10 * time.Second
	b := New(cfg)
	now := time.Date(2026, time.March, 30, 0, 0, 0, 0, time.UTC)

	if !b.Allow(now) {
		t.Fatalf("closed breaker should allow")
	}

	b.OnFailure(now)
	b.OnFailure(now)
	if b.State(now) != StateClosed {
		t.Fatalf("expected closed before threshold")
	}

	b.OnFailure(now)
	if b.State(now) != StateOpen {
		t.Fatalf("expected open after threshold")
	}
	if b.Allow(now) {
		t.Fatalf("open breaker should deny")
	}

	now = now.Add(11 * time.Second)
	if b.State(now) != StateHalfOpen {
		t.Fatalf("expected half-open after open duration")
	}
	if !b.Allow(now) {
		t.Fatalf("half-open should allow probe")
	}
	b.OnSuccess(now)
	if !b.Allow(now) {
		t.Fatalf("half-open should allow second probe")
	}
	b.OnSuccess(now)
	if b.State(now) != StateClosed {
		t.Fatalf("expected closed after success threshold")
	}
}

func TestBreakerHalfOpenFailureReopens(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OpenDuration = time.Second
	b := New(cfg)
	now := time.Now()

	b.OnFailure(now)
	b.OnFailure(now)
	b.OnFailure(now)
	if b.State(now) != StateOpen {
		t.Fatalf("expected open state")
	}

	now = now.Add(2 * time.Second)
	if !b.Allow(now) {
		t.Fatalf("expected half-open probe")
	}
	b.OnFailure(now)
	if b.State(now) != StateOpen {
		t.Fatalf("expected reopen on half-open failure")
	}
}
