package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestMakePromptBuildCacheKeyUsesHookActionAndPromptHash(t *testing.T) {
	key := makePromptBuildCacheKey("snap-1", "tenant-a", "before_prompt_build", "CONSTRAIN", "summarize sk-TESTKEY-DONTLEAK")
	if !strings.Contains(key, "before_prompt_build|CONSTRAIN|") {
		t.Fatalf("expected hook and action in cache key, got %q", key)
	}
	if strings.Contains(key, "sk-TESTKEY-DONTLEAK") {
		t.Fatalf("cache key leaked prompt literal: %q", key)
	}

	otherPrompt := makePromptBuildCacheKey("snap-1", "tenant-a", "before_prompt_build", "CONSTRAIN", "summarize project status")
	if key == otherPrompt {
		t.Fatalf("expected prompt hash to change when prompt text changes")
	}

	otherHook := makePromptBuildCacheKey("snap-1", "tenant-a", "before_tool_execution", "CONSTRAIN", "summarize sk-TESTKEY-DONTLEAK")
	if key == otherHook {
		t.Fatalf("expected hook to change prompt cache key")
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

func TestCheckPromptBuildConstrainsSecretPrompt(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	payload := CheckRequest{Tool: "prompt_build", Hook: "before_prompt_build", PromptText: "summarize sk-TESTKEY-DONTLEAK", Agent: "agent-1", Model: "gpt-4.1-mini"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "CONSTRAIN" {
		t.Fatalf("decision = %q, want CONSTRAIN", response.Decision)
	}
	if response.Constraints["kind"] != "prompt_redact" {
		t.Fatalf("constraint kind = %#v, want prompt_redact", response.Constraints["kind"])
	}
	modified, _ := response.Constraints["modified_prompt"].(string)
	if !strings.Contains(modified, "<REDACTED-OPENAI_KEY>") {
		t.Fatalf("modified prompt = %q, want redaction placeholder", modified)
	}
	if strings.Contains(modified, "sk-TESTKEY-DONTLEAK") {
		t.Fatalf("modified prompt leaked secret: %q", modified)
	}
}

func TestCheckPromptBuildUsesPromptCache(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5 * 60 * 1000000000, FailMode: "closed"}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	payload := CheckRequest{Tool: "prompt_build", Hook: "before_prompt_build", PromptText: "summarize sk-TESTKEY-DONTLEAK", Agent: "agent-1"}
	body, _ := json.Marshal(payload)

	req1 := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w1 := httptest.NewRecorder()
	h.Router().ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first status = %d, body = %s", w1.Code, w1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w2 := httptest.NewRecorder()
	h.Router().ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second status = %d, body = %s", w2.Code, w2.Body.String())
	}

	var response PolicyResponse
	if err := json.NewDecoder(w2.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Cached {
		t.Fatalf("expected second prompt build response to be cached")
	}
}

func TestCheckPromptBuildUsesConfiguredDLPPolicy(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	if err := os.WriteFile(policyPath, []byte(`
prompt_pii_redact:
  action: DENY
  reason: block prompt credential leakage
  patterns:
    - name: CUSTOM_EMPLOYEE_ID
      regex: '\bEMP-\d{6}\b'
      placeholder: '<REDACTED-CUSTOM_EMPLOYEE_ID>'
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed", DLPPolicyPath: policyPath}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	payload := CheckRequest{Tool: "prompt_build", Hook: "before_prompt_build", PromptText: "summarize employee EMP-123456", Agent: "agent-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "DENY" {
		t.Fatalf("decision = %q, want DENY", response.Decision)
	}
	if !strings.Contains(response.Reason, "CUSTOM_EMPLOYEE_ID") {
		t.Fatalf("reason = %q, want custom pattern name", response.Reason)
	}
}

func TestCheckPromptBuildAllowsSafePrompt(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	payload := CheckRequest{Tool: "prompt_build", Hook: "before_prompt_build", PromptText: "summarize project status", Agent: "agent-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW", response.Decision)
	}
	if response.Constraints != nil {
		t.Fatalf("constraints = %#v, want nil", response.Constraints)
	}
}

func TestCheckPromptBuildDeniesOversizedPrompt(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	payload := CheckRequest{Tool: "prompt_build", Hook: "before_prompt_build", PromptText: strings.Repeat("a", 1<<20+1), Agent: "agent-1"}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "DENY" {
		t.Fatalf("decision = %q, want DENY", response.Decision)
	}
	if response.Reason != "prompt_too_large" {
		t.Fatalf("reason = %q, want prompt_too_large", response.Reason)
	}
}
