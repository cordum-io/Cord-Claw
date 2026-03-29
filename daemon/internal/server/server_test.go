package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
