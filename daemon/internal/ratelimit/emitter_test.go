package ratelimit

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAllow_WithinLimit(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	emitter := New(50, nil, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return base }

	for i := 0; i < 50; i++ {
		if got := emitter.Allow("agent-a"); got != true {
			t.Fatalf("Allow(%d) = %v, want true", i, got)
		}
	}
}

func TestAllow_AboveLimit_Caps(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	emitter := New(50, nil, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return base }

	var allowed, denied int
	for i := 0; i < 200; i++ {
		if emitter.Allow("agent-a") {
			allowed++
		} else {
			denied++
		}
	}

	if allowed != 50 {
		t.Fatalf("allowed = %d, want 50", allowed)
	}
	if denied != 150 {
		t.Fatalf("denied = %d, want 150", denied)
	}
}

func TestAllow_CrossAgentIsolation(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	emitter := New(50, nil, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return base }

	for i := 0; i < 50; i++ {
		if got := emitter.Allow("agent-a"); got != true {
			t.Fatalf("agent-a Allow(%d) = %v, want true", i, got)
		}
		if got := emitter.Allow("agent-b"); got != true {
			t.Fatalf("agent-b Allow(%d) = %v, want true", i, got)
		}
	}
}

func TestAllow_RefillAcrossWindows(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	now := base
	emitter := New(50, nil, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return now }

	for i := 0; i < 50; i++ {
		if got := emitter.Allow("agent-a"); got != true {
			t.Fatalf("first window Allow(%d) = %v, want true", i, got)
		}
	}

	now = base.Add(time.Second)
	for i := 0; i < 50; i++ {
		if got := emitter.Allow("agent-a"); got != true {
			t.Fatalf("second window Allow(%d) = %v, want true", i, got)
		}
	}
}

func TestSummary_FiresOncePerSecond(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	summaries := make(chan int, 4)
	emitter := New(50, func(agentID string, count int) {
		if agentID != "agent-a" {
			t.Errorf("summary agentID = %q, want agent-a", agentID)
		}
		summaries <- count
	}, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return base }

	for i := 0; i < 150; i++ {
		_ = emitter.Allow("agent-a")
	}

	select {
	case count := <-summaries:
		if count != 100 {
			t.Fatalf("summary count = %d, want 100", count)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("summary callback did not fire within 1.5s")
	}

	select {
	case count := <-summaries:
		t.Fatalf("unexpected second summary callback with count %d", count)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestGC_TTLEviction(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	now := base
	emitter := New(50, nil, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return now }

	if got := emitter.Allow("agent-a"); got != true {
		t.Fatalf("initial Allow = %v, want true", got)
	}
	if entries := len(emitter.limiters); entries != 1 {
		t.Fatalf("entries before GC = %d, want 1", entries)
	}

	now = base.Add(time.Hour + time.Second)
	emitter.GC()
	if entries := len(emitter.limiters); entries != 0 {
		t.Fatalf("entries after GC = %d, want 0", entries)
	}

	for i := 0; i < 50; i++ {
		if got := emitter.Allow("agent-a"); got != true {
			t.Fatalf("post-GC Allow(%d) = %v, want true", i, got)
		}
	}
}

func TestAllow_Concurrent(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	emitter := New(50, nil, prometheus.NewRegistry())
	defer emitter.Close()
	emitter.now = func() time.Time { return base }

	var wg sync.WaitGroup
	allowedCh := make(chan bool, 200)
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				allowedCh <- emitter.Allow("agent-a")
			}
		}()
	}
	wg.Wait()
	close(allowedCh)

	var allowed, denied int
	for ok := range allowedCh {
		if ok {
			allowed++
		} else {
			denied++
		}
	}
	if allowed != 50 {
		t.Fatalf("allowed = %d, want 50", allowed)
	}
	if denied != 150 {
		t.Fatalf("denied = %d, want 150", denied)
	}
}

func TestMetric_RateLimitedTotalIncrements(t *testing.T) {
	base := time.Now().Truncate(time.Second)
	reg := prometheus.NewRegistry()
	emitter := New(50, nil, reg)
	defer emitter.Close()
	emitter.now = func() time.Time { return base }

	for i := 0; i < 200; i++ {
		_ = emitter.Allow("agent-a")
	}

	if got := testutil.ToFloat64(emitter.metricRateLimited); got != 150 {
		t.Fatalf("cordclaw_rate_limited_total = %v, want 150", got)
	}
}
