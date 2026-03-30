package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/client"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
)

type fakeSafety struct {
	decision cache.Decision
	err      error
}

func (f *fakeSafety) Check(context.Context, mapper.PolicyCheckRequest) (cache.Decision, error) {
	if f.err != nil {
		return cache.Decision{}, f.err
	}
	return f.decision, nil
}

func (f *fakeSafety) Health(context.Context) client.Health {
	return client.Health{Connected: f.err == nil, State: "ready"}
}

func (f *fakeSafety) Close() error { return nil }

func TestCheckUsesCacheAfterFirstCall(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 0, FailMode: "graduated"}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	h.cfg.CacheTTL = 5 * 60 * 1000000000 // 5m

	payload := CheckRequest{Tool: "exec", Command: "echo hi"}
	body, _ := json.Marshal(payload)

	req1 := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w1 := httptest.NewRecorder()
	h.Router().ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w2 := httptest.NewRecorder()
	h.Router().ServeHTTP(w2, req2)

	var response PolicyResponse
	if err := json.NewDecoder(w2.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Cached {
		t.Fatalf("expected second response to be cached")
	}
}

func TestMakeCacheKeyDeterministicIgnoresSession(t *testing.T) {
	base := mapper.PolicyCheckRequest{
		Topic:      "job.cordclaw.exec",
		Capability: "cordclaw.shell-execute",
		Tool:       "exec",
		Command:    "echo hi",
		Agent:      "agent-1",
		RiskTags:   []string{"exec", "system", "write"},
	}

	withSessionA := base
	withSessionA.Session = "session-a"
	withSessionB := base
	withSessionB.Session = "session-b"

	keyA := makeCacheKey("snap-1", "tenant-a", withSessionA)
	keyB := makeCacheKey("snap-1", "tenant-a", withSessionB)

	if keyA != keyB {
		t.Fatalf("expected cache key to ignore session; got %q vs %q", keyA, keyB)
	}
	if !strings.HasPrefix(keyA, "snap-1:") {
		t.Fatalf("expected snapshot prefix in cache key, got %q", keyA)
	}
}

func TestMakeCacheKeyChangesForDifferentRequest(t *testing.T) {
	left := mapper.PolicyCheckRequest{
		Topic:      "job.cordclaw.exec",
		Capability: "cordclaw.shell-execute",
		Tool:       "exec",
		Command:    "echo safe",
		Agent:      "agent-1",
		RiskTags:   []string{"exec", "system", "write"},
	}
	right := left
	right.Command = "rm -rf /"
	right.RiskTags = []string{"destructive", "exec", "system", "write"}

	keyLeft := makeCacheKey("snap-1", "tenant-a", left)
	keyRight := makeCacheKey("snap-1", "tenant-a", right)

	if keyLeft == keyRight {
		t.Fatalf("expected cache key to change when semantic request fields change")
	}
}

func TestCheckFailModeClosedDenies(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, &fakeSafety{err: context.DeadlineExceeded})

	payload := CheckRequest{Tool: "exec", Command: "echo hi"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)

	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "DENY" {
		t.Fatalf("expected DENY, got %s", response.Decision)
	}
	if response.GovernanceStatus != "offline" {
		t.Fatalf("expected offline status, got %s", response.GovernanceStatus)
	}
}
