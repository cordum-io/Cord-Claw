package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
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
	requests []mapper.PolicyCheckRequest
}

func (f *fakeSafety) Check(_ context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error) {
	f.requests = append(f.requests, req)
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
	if len(h.gating.(*fakeSafety).requests) != 1 {
		t.Fatalf("gating requests = %d, want 1", len(h.gating.(*fakeSafety).requests))
	}
	t.Logf("server cache-hit evidence: cached=%v gating_requests=%d", response.Cached, len(h.gating.(*fakeSafety).requests))
}

func TestCheckUsesGatingClientWithHookAndEnvelope(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, safety)

	payload := map[string]any{
		"tool":             "web_fetch",
		"hook":             "before_tool_execution",
		"hookType":         "before_tool_execution",
		"url":              "https://example.test/report",
		"agent":            "agent-1",
		"session":          "session-1",
		"turnOrigin":       "user",
		"openclaw_version": "0.9.0-test",
		"openclawVersion":  "0.9.0-test",
		"turn_origin":      "user",
		"envelope":         map[string]any{"url": "https://example.test/report"},
	}
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
	if len(safety.requests) != 1 {
		t.Fatalf("gating requests = %d, want 1", len(safety.requests))
	}
	got := safety.requests[0]
	if got.HookName != "before_tool_execution" {
		t.Fatalf("HookName = %q, want before_tool_execution", got.HookName)
	}
	if got.Tool != "web_fetch" {
		t.Fatalf("Tool = %q, want web_fetch", got.Tool)
	}
	if got.OpenClawVersion != "0.9.0-test" {
		t.Fatalf("OpenClawVersion = %q, want 0.9.0-test", got.OpenClawVersion)
	}
	if got.Envelope["url"] != "https://example.test/report" {
		t.Fatalf("Envelope.url = %#v, want https://example.test/report", got.Envelope["url"])
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

func TestCheckCronCreateAllowThenAgentStartSameCronAllows(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, safety)

	cronCreate := CheckRequest{Tool: "cron.create", CronJobID: "cron-7", Agent: "agent-1", Session: "session-parent"}
	body, _ := json.Marshal(cronCreate)
	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("cron_create status = %d, body = %s", w.Code, w.Body.String())
	}

	agentStart := CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "cron",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "cron:cron-7",
	}
	body, _ = json.Marshal(agentStart)
	req = httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w = httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("agent_start status = %d, body = %s", w.Code, w.Body.String())
	}

	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW", response.Decision)
	}
	if len(safety.requests) != 2 {
		t.Fatalf("safety requests = %d, want 2", len(safety.requests))
	}
	if safety.requests[1].Topic != "job.openclaw.agent_start" {
		t.Fatalf("agent_start topic = %q", safety.requests[1].Topic)
	}
	if containsString(safety.requests[1].RiskTags, "cron_fire") {
		t.Fatalf("known cron safety request should not retain cron_fire deny tag: %v", safety.requests[1].RiskTags)
	}
	if !containsString(safety.requests[1].RiskTags, "cron_origin_verified") {
		t.Fatalf("known cron safety request missing cron_origin_verified tag: %v", safety.requests[1].RiskTags)
	}
}

func TestCheckAgentStartUnknownCronDeniesBeforeSafety(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed", LogDecisions: true}, safety)

	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldWriter)

	payload := CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "cron",
		CronJobID:  "unknown-fake",
		Agent:      "agent-1",
		Session:    "cron:unknown-fake",
	}
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
	if response.Reason != "cron-origin-policy-mismatch" {
		t.Fatalf("reason = %q, want cron-origin-policy-mismatch", response.Reason)
	}
	if len(safety.requests) != 0 {
		t.Fatalf("expected cron-origin DENY before safety, got %d safety calls", len(safety.requests))
	}
	if !strings.Contains(logBuf.String(), "action=agent_start decision=DENY reason=cron-origin-policy-mismatch") {
		t.Fatalf("missing expected denial log line: %s", logBuf.String())
	}
}

func TestCheckAgentStartUserOriginAllowsByDefault(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, safety)

	payload := CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "user",
		Agent:      "agent-1",
		Session:    "session-user",
	}
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
	if len(safety.requests) != 1 {
		t.Fatalf("safety requests = %d, want 1", len(safety.requests))
	}
	if safety.requests[0].Topic != "job.openclaw.agent_start" {
		t.Fatalf("topic = %q, want job.openclaw.agent_start", safety.requests[0].Topic)
	}
}

func TestCheckUnknownHookTypeReturnsBadRequest(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed"}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	payload := CheckRequest{Tool: "agent_start", HookType: "before_session_start", Agent: "agent-1", Session: "session-1"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
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
