package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/client"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
	"github.com/cordum-io/cordclaw/daemon/internal/policy"
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

func testBoolPtr(v bool) *bool { return &v }

func TestNewLoadsShadowRulesFromDLPPolicyPath(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	if err := os.WriteFile(policyPath, []byte(`
prompt_pii_redact:
  action: CONSTRAIN
  reason: redact prompt credentials
  patterns:
    - name: TEST_TOKEN
      regex: 'TEST-[A-Z]+'
      placeholder: '<REDACTED-TEST_TOKEN>'
rules:
  - id: shadow-deny-web-fetch-from-file
    enforce: false
    match:
      topics: [job.openclaw.tool_call]
      risk_tags: [network, read]
    decision: deny
    reason: loaded shadow rule from policy file
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "gateway allow", Snapshot: "snap-1"}}
	events := make(chan policy.ShadowEvent, 1)
	h := newWithShadowEventCallback(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50, DLPPolicyPath: policyPath}, safety, func(ev policy.ShadowEvent) {
		events <- ev
	})
	defer h.Close()

	body, _ := json.Marshal(CheckRequest{Tool: "web_fetch", URL: "https://docs.cordum.io", Agent: "agent-shadow-file"})
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	select {
	case ev := <-events:
		if ev.RuleID != "shadow-deny-web-fetch-from-file" || ev.WouldDecision != "DENY" {
			t.Fatalf("shadow event = %#v, want loaded shadow DENY", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shadow event loaded from DLPPolicyPath")
	}
}

func TestShadowPolicySmokeTenCacheMisses(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	if err := os.WriteFile(policyPath, []byte(`
prompt_pii_redact:
  action: CONSTRAIN
  reason: redact prompt credentials
  patterns:
    - name: TEST_TOKEN
      regex: 'TEST-[A-Z]+'
      placeholder: '<REDACTED-TEST_TOKEN>'
rules:
  - id: openclaw-shadow-strict-web-fetch
    enforce: false
    match:
      topics: [job.openclaw.tool_call]
      risk_tags: [network, read]
    decision: deny
    reason: Future stricter web_fetch policy would block network read tool calls.
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "gateway allow", Snapshot: "snap-1"}}
	events := make(chan policy.ShadowEvent, 10)
	h := newWithShadowEventCallback(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50, DLPPolicyPath: policyPath}, safety, func(ev policy.ShadowEvent) {
		events <- ev
	})
	defer h.Close()

	for i := 0; i < 10; i++ {
		body, _ := json.Marshal(CheckRequest{Tool: "web_fetch", URL: fmt.Sprintf("https://docs.cordum.io/shadow-smoke-%d", i), Agent: "agent-shadow-smoke"})
		w := httptest.NewRecorder()
		h.Router().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, body = %s", i, w.Code, w.Body.String())
		}
		var response PolicyResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode response %d: %v", i, err)
		}
		if response.Decision != "ALLOW" || response.Cached {
			t.Fatalf("response %d = %#v, want uncached gateway ALLOW", i, response)
		}
	}

	for i := 0; i < 10; i++ {
		select {
		case ev := <-events:
			if ev.RuleID != "openclaw-shadow-strict-web-fetch" || ev.WouldDecision != "DENY" {
				t.Fatalf("event %d = %#v, want shadow DENY", i, ev)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for shadow event %d", i)
		}
	}
	if len(events) != 0 {
		t.Fatalf("extra shadow events = %d, want 0", len(events))
	}

	metrics := httptest.NewRecorder()
	h.Router().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "cordclaw_shadow_events_total 10") {
		t.Fatalf("metrics missing shadow counter value 10: %s", metrics.Body.String())
	}
}

func TestCheckEmitsShadowEventWithoutChangingRealDecision(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "gateway allow", Snapshot: "snap-1"}}
	events := make(chan policy.ShadowEvent, 1)
	h := newWithShadowEventCallback(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, safety, func(ev policy.ShadowEvent) {
		events <- ev
	})
	defer h.Close()
	h.shadowRules = []policy.Rule{
		{
			ID:       "shadow-deny-web-fetch",
			Match:    policy.MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network", "read"}},
			Decision: "deny",
			Reason:   "future stricter network-read rule",
			Enforce:  testBoolPtr(false),
		},
	}

	payload := CheckRequest{Tool: "web_fetch", URL: "https://docs.cordum.io", Agent: "agent-shadow"}
	body, _ := json.Marshal(payload)
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "ALLOW" || response.Reason != "gateway allow" {
		t.Fatalf("response = %#v, want unchanged gateway ALLOW", response)
	}

	select {
	case ev := <-events:
		if ev.RuleID != "shadow-deny-web-fetch" || ev.WouldDecision != "DENY" || ev.WouldReason != "future stricter network-read rule" || ev.HookName != "before_tool_execution" {
			t.Fatalf("shadow event = %#v", ev)
		}
		wantLabels := map[string]string{
			"cordclaw.shadow":         "true",
			"cordclaw.rule_id":        "shadow-deny-web-fetch",
			"cordclaw.would_decision": "DENY",
			"cordclaw.would_reason":   "future stricter network-read rule",
			"cordclaw.hook_name":      "before_tool_execution",
		}
		if got := ev.Labels(); !reflect.DeepEqual(got, wantLabels) {
			t.Fatalf("shadow labels = %#v, want %#v", got, wantLabels)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for shadow event callback")
	}

	metrics := httptest.NewRecorder()
	h.Router().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "cordclaw_shadow_events_total 1") {
		t.Fatalf("metrics missing shadow counter increment: %s", metrics.Body.String())
	}
}

func TestCheckSkipsShadowEventOnCacheHit(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "gateway allow", Snapshot: "snap-1"}}
	events := make(chan policy.ShadowEvent, 2)
	h := newWithShadowEventCallback(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, safety, func(ev policy.ShadowEvent) {
		events <- ev
	})
	defer h.Close()
	h.shadowRules = []policy.Rule{
		{
			ID:       "shadow-deny-web-fetch",
			Match:    policy.MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network", "read"}},
			Decision: "deny",
			Reason:   "future stricter network-read rule",
			Enforce:  testBoolPtr(false),
		},
	}

	payload := CheckRequest{Tool: "web_fetch", URL: "https://docs.cordum.io", Agent: "agent-shadow-cache"}
	body, _ := json.Marshal(payload)
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.Router().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, body = %s", i+1, w.Code, w.Body.String())
		}
		var response PolicyResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode response %d: %v", i+1, err)
		}
		if i == 1 && !response.Cached {
			t.Fatalf("second response cached = false, want true")
		}
	}
	if len(safety.requests) != 1 {
		t.Fatalf("gating requests = %d, want 1 cache miss", len(safety.requests))
	}
	select {
	case <-events:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first shadow event")
	}
	select {
	case ev := <-events:
		t.Fatalf("unexpected shadow event on cache hit: %#v", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

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

func TestCheckRateLimitDeniesBeforeCacheAndGating(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 1}, safety)
	defer h.Close()

	body, _ := json.Marshal(CheckRequest{Tool: "exec", Command: "echo hi", Agent: "agent-a"})
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.Router().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, body = %s", i, w.Code, w.Body.String())
		}
		if i == 1 {
			var response PolicyResponse
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.Decision != "DENY" {
				t.Fatalf("second decision = %q, want DENY", response.Decision)
			}
			if response.Reason != "rate_limited" {
				t.Fatalf("second reason = %q, want rate_limited", response.Reason)
			}
		}
	}
	if len(safety.requests) != 1 {
		t.Fatalf("gating requests = %d, want 1", len(safety.requests))
	}
}

func TestMetricsEndpointExposesRateLimitCounter(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cordclaw_rate_limited_total") {
		t.Fatalf("metrics body missing cordclaw_rate_limited_total: %s", w.Body.String())
	}
}

func TestCheckRateLimitWithinLimitAllows(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-within", 49)
	if counts["ALLOW"] != 49 {
		t.Fatalf("ALLOW count = %d, want 49 (all counts: %#v)", counts["ALLOW"], counts)
	}
	if counts["DENY"] != 0 {
		t.Fatalf("DENY count = %d, want 0 (all counts: %#v)", counts["DENY"], counts)
	}
}

func TestCheckRateLimitOverLimitDeniesExcess(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-over", 200)
	if counts["ALLOW"] != 50 {
		t.Fatalf("ALLOW count = %d, want 50 (all counts: %#v)", counts["ALLOW"], counts)
	}
	if counts["rate_limited"] != 150 {
		t.Fatalf("rate_limited count = %d, want 150 (all counts: %#v)", counts["rate_limited"], counts)
	}
}

func TestCheckRateLimitCrossAgentIsolation(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	agentA := runCheckBurst(t, h, "agent-a", 200)
	agentB := runCheckBurst(t, h, "agent-b", 50)
	if agentA["ALLOW"] != 50 || agentA["rate_limited"] != 150 {
		t.Fatalf("agent-a counts = %#v, want ALLOW=50 rate_limited=150", agentA)
	}
	if agentB["ALLOW"] != 50 || agentB["rate_limited"] != 0 {
		t.Fatalf("agent-b counts = %#v, want ALLOW=50 rate_limited=0", agentB)
	}
}

func TestMetricsEndpointShowsNonZeroRateLimitCounterAfterBurst(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-metrics", 200)
	if counts["rate_limited"] != 150 {
		t.Fatalf("rate_limited count = %d, want 150", counts["rate_limited"])
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cordclaw_rate_limited_total 150") {
		t.Fatalf("metrics body missing non-zero counter 150: %s", w.Body.String())
	}
}

func TestCheckRateLimitEnvOverrideCapsAtTen(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")
	t.Setenv("CORDCLAW_EMIT_RATE_LIMIT", "10")
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	h := New(cfg, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-env", 11)
	if counts["ALLOW"] != 10 {
		t.Fatalf("ALLOW count = %d, want 10 (all counts: %#v)", counts["ALLOW"], counts)
	}
	if counts["rate_limited"] != 1 {
		t.Fatalf("rate_limited count = %d, want 1 (all counts: %#v)", counts["rate_limited"], counts)
	}
}

func TestEmitRateLimit_DefaultIs50(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-default-50", 51)
	if counts["ALLOW"] != 50 || counts["rate_limited"] != 1 {
		t.Fatalf("counts = %#v, want ALLOW=50 rate_limited=1", counts)
	}
}

func TestEmitRateLimit_EnvOverride(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 10}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-env-override", 11)
	if counts["ALLOW"] != 10 || counts["rate_limited"] != 1 {
		t.Fatalf("counts = %#v, want ALLOW=10 rate_limited=1", counts)
	}
}

func TestEmitRateLimit_PolicyOverride_LowersDefault(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1", Constraints: map[string]any{"cordclaw.emit_rate_limit_rps": 5}}})
	defer h.Close()

	seed := runCheckBurst(t, h, "agent-policy-lower", 1)
	if seed["ALLOW"] != 1 || seed["rate_limited"] != 0 {
		t.Fatalf("seed counts = %#v, want exactly one default-allowed request", seed)
	}
	time.Sleep(1100 * time.Millisecond)

	counts := runCheckBurst(t, h, "agent-policy-lower", 6)
	if counts["ALLOW"] != 5 || counts["rate_limited"] != 1 {
		t.Fatalf("post-policy counts = %#v, want ALLOW=5 rate_limited=1", counts)
	}
}

func TestEmitRateLimit_PolicyOverride_RaisesDefault(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 300, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1", Constraints: map[string]any{"cordclaw.emit_rate_limit_rps": 200}}})
	defer h.Close()

	seed := runCheckBurst(t, h, "agent-policy-higher", 1)
	if seed["ALLOW"] != 1 || seed["rate_limited"] != 0 {
		t.Fatalf("seed counts = %#v, want exactly one default-allowed request", seed)
	}
	time.Sleep(1100 * time.Millisecond)

	allowedBurst := runCheckBurst(t, h, "agent-policy-higher", 200)
	if allowedBurst["ALLOW"] != 200 || allowedBurst["rate_limited"] != 0 {
		t.Fatalf("raised-limit burst counts = %#v, want ALLOW=200 rate_limited=0", allowedBurst)
	}
	denied := runCheckBurst(t, h, "agent-policy-higher", 1)
	if denied["rate_limited"] != 1 || denied["ALLOW"] != 0 {
		t.Fatalf("201st request counts = %#v, want exactly one rate_limited DENY", denied)
	}
}

func TestEmitRateLimit_MaliciousClientLabelIgnored(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	counts := runCheckBurstRequest(t, h, CheckRequest{
		Tool:    "exec",
		Command: "echo hi",
		AgentID: "agent-malicious-label",
		Labels:  map[string]string{"cordclaw.emit_rate_limit": "999"},
	}, 51)
	if counts["ALLOW"] != 50 || counts["rate_limited"] != 1 {
		t.Fatalf("counts = %#v, want ALLOW=50 rate_limited=1 with client label ignored", counts)
	}
}

func TestPolicyRateLimitCacheIsPerAgentAndClearedBySnapshot(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	h.recordPolicyRateLimit("agent-policy-cache-a", cache.Decision{Constraints: map[string]any{"cordclaw.emit_rate_limit_rps": 5}})
	if limit, ok := h.lookupPolicyRateLimit("agent-policy-cache-a"); !ok || limit != 5 {
		t.Fatalf("agent-policy-cache-a limit = %v ok=%v, want 5 true", limit, ok)
	}
	if limit, ok := h.lookupPolicyRateLimit("agent-policy-cache-b"); ok {
		t.Fatalf("agent-policy-cache-b inherited limit %v, want no override", limit)
	}

	h.updateSnapshot("snap-2")
	if limit, ok := h.lookupPolicyRateLimit("agent-policy-cache-a"); ok {
		t.Fatalf("agent-policy-cache-a limit after snapshot rotation = %v, want no override", limit)
	}
}

func TestPolicyRateLimitIgnoresInvalidConstraints(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	invalidValues := []any{
		0,
		0.5,
		-1,
		1000.1,
		math.NaN(),
		math.Inf(1),
		"not-a-number",
		"0",
		"1000.1",
		struct{}{},
	}
	for i, raw := range invalidValues {
		agentID := "agent-invalid-" + strconv.Itoa(i)
		h.recordPolicyRateLimit(agentID, cache.Decision{Constraints: map[string]any{"cordclaw.emit_rate_limit_rps": raw}})
		if limit, ok := h.lookupPolicyRateLimit(agentID); ok {
			t.Fatalf("invalid constraint %T(%v) recorded limit %v for %s", raw, raw, limit, agentID)
		}
	}
}

func TestPolicyRateLimitRecordsDenyDecisionConstraint(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	h.recordPolicyRateLimit("agent-deny-constraint", cache.Decision{
		Decision:    "DENY",
		Reason:      "blocked by policy",
		Constraints: map[string]any{"cordclaw.emit_rate_limit_rps": json.Number("7")},
	})
	if limit, ok := h.lookupPolicyRateLimit("agent-deny-constraint"); !ok || limit != 7 {
		t.Fatalf("deny decision limit = %v ok=%v, want 7 true", limit, ok)
	}
}

func TestPolicyRateLimitConcurrentAccess(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	defer h.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			agentID := "agent-concurrent-" + strconv.Itoa(i)
			want := float64((i % 20) + 1)
			h.recordPolicyRateLimit(agentID, cache.Decision{Constraints: map[string]any{"cordclaw.emit_rate_limit_rps": want}})
			if got, ok := h.lookupPolicyRateLimit(agentID); !ok || got != want {
				t.Errorf("%s limit = %v ok=%v, want %v true", agentID, got, ok, want)
			}
		}()
	}
	wg.Wait()
}

func TestCheckRateLimitSummaryCallback(t *testing.T) {
	summaries := make(chan int, 4)
	h := newWithRateLimitSummary(config.Config{CacheMaxSize: 100, CacheTTL: time.Minute, FailMode: "closed", EmitRateLimit: 50}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}, func(agentID string, count int) {
		if agentID != "agent-summary" {
			t.Errorf("summary agentID = %q, want agent-summary", agentID)
		}
		summaries <- count
	})
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-summary", 200)
	if counts["rate_limited"] != 150 {
		t.Fatalf("rate_limited count = %d, want 150", counts["rate_limited"])
	}

	select {
	case count := <-summaries:
		if count != 150 {
			t.Fatalf("summary count = %d, want 150", count)
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("summary callback did not fire within 1.5s")
	}
}

func TestCheckRateLimitSummaryJobEmittedViaCordumGateway(t *testing.T) {
	var mu sync.Mutex
	var jobs []map[string]any
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/jobs" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		jobs = append(jobs, body)
		mu.Unlock()
		writeJSON(w, http.StatusAccepted, map[string]any{
			"job_id":          "job-test",
			"safety_decision": "ALLOW",
			"safety_reason":   "ok",
			"safety_snapshot": "snap-1",
		})
	}))
	defer gateway.Close()

	h := New(config.Config{
		CordumGatewayURL: gateway.URL,
		CordumAPIKey:     "test-key",
		APIKey:           "test-key",
		TenantID:         "tenant-a",
		CacheMaxSize:     100,
		CacheTTL:         time.Minute,
		FailMode:         "closed",
		EmitRateLimit:    50,
	}, nil)
	defer h.Close()

	counts := runCheckBurst(t, h, "agent-summary-job", 200)
	if counts["rate_limited"] != 150 {
		t.Fatalf("rate_limited count = %d, want 150 (all counts: %#v)", counts["rate_limited"], counts)
	}

	var summaries []map[string]any
	deadline := time.After(1500 * time.Millisecond)
	for len(summaries) == 0 {
		select {
		case <-deadline:
			t.Fatalf("summary job was not emitted; all jobs: %#v", snapshotJobs(&mu, jobs))
		case <-time.After(25 * time.Millisecond):
			summaries = summaryJobs(snapshotJobs(&mu, jobs))
		}
	}
	if len(summaries) != 1 {
		t.Fatalf("summary job count = %d, want 1 (summaries: %#v)", len(summaries), summaries)
	}
	labels, ok := summaries[0]["labels"].(map[string]any)
	if !ok {
		t.Fatalf("summary labels = %T, want object: %#v", summaries[0]["labels"], summaries[0])
	}
	if labels["cordclaw.rate_limited"] != "true" {
		t.Fatalf("cordclaw.rate_limited label = %#v, want true", labels["cordclaw.rate_limited"])
	}
	if labels["denied_count"] != "150" {
		t.Fatalf("denied_count label = %#v, want 150", labels["denied_count"])
	}
	if labels["agent_id"] != "agent-summary-job" {
		t.Fatalf("agent_id label = %#v, want agent-summary-job", labels["agent_id"])
	}
	windowStartStr, ok := labels["window_start"].(string)
	if !ok || windowStartStr == "" {
		t.Fatalf("window_start label missing or not a string: %#v", labels["window_start"])
	}
	windowStart, err := strconv.ParseInt(windowStartStr, 10, 64)
	if err != nil || windowStart <= 0 {
		t.Fatalf("window_start label = %#v, want positive int64: parse err=%v", windowStartStr, err)
	}

	// Recursion guard: the summary callback in server.go calls
	// submitter.Submit directly, bypassing h.handleCheck/h.emitter — so
	// the summary itself cannot consume a per-agent rate-limit slot or
	// trigger another summary. We do not assert "1 policy-check + 1
	// summary == 51" here because the cache (CacheMaxSize=100,
	// CacheTTL=1min) dedupes identical /check payloads, so only the
	// first allowed-through check posts to the gateway and the rest are
	// cache hits. The combination of (a) counts["rate_limited"] == 150
	// (no inflation from self-recursion) and (b) len(summaries) == 1
	// (no second summary from a re-entrant emitter increment) already
	// proves the structural invariant from the architectural callsite.
	allJobs := snapshotJobs(&mu, jobs)
	policyCheckJobs := len(allJobs) - len(summaries)
	if policyCheckJobs < 1 {
		t.Fatalf("expected at least one policy-check job to land alongside the summary, got %d (allJobs=%d, summaries=%d)", policyCheckJobs, len(allJobs), len(summaries))
	}
}

func TestCheckEmitsShadowEventViaCordumGateway(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	if err := os.WriteFile(policyPath, []byte(`
rules:
  - id: openclaw-shadow-strict-web-fetch
    enforce: false
    match:
      topics: [job.openclaw.tool_call]
      risk_tags: [network, read]
    decision: deny
    reason: Future stricter web_fetch policy would block network read tool calls.
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	var mu sync.Mutex
	var jobs []map[string]any
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/jobs" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("X-API-Key"); got != "test-key" {
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		jobs = append(jobs, body)
		mu.Unlock()
		writeJSON(w, http.StatusAccepted, map[string]any{
			"job_id":          "job-test",
			"safety_decision": "ALLOW",
			"safety_reason":   "ok",
			"safety_snapshot": "snap-1",
		})
	}))
	defer gateway.Close()

	h := New(config.Config{
		CordumGatewayURL: gateway.URL,
		CordumAPIKey:     "test-key",
		APIKey:           "test-key",
		TenantID:         "tenant-a",
		CacheMaxSize:     100,
		CacheTTL:         time.Minute,
		FailMode:         "closed",
		EmitRateLimit:    50,
		ShadowPolicyPath: policyPath,
	}, nil)
	defer h.Close()

	body, _ := json.Marshal(CheckRequest{Tool: "web_fetch", URL: "https://docs.cordum.io/shadow-live", Agent: "agent-shadow-job"})
	w := httptest.NewRecorder()
	h.Router().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var response PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision != "ALLOW" {
		t.Fatalf("real decision = %q, want ALLOW (body=%s)", response.Decision, w.Body.String())
	}

	var shadows []map[string]any
	deadline := time.After(1500 * time.Millisecond)
	for len(shadows) == 0 {
		select {
		case <-deadline:
			t.Fatalf("shadow job was not emitted; all jobs: %#v", snapshotJobs(&mu, jobs))
		case <-time.After(25 * time.Millisecond):
			shadows = shadowJobs(snapshotJobs(&mu, jobs))
		}
	}
	if len(shadows) != 1 {
		t.Fatalf("shadow job count = %d, want 1 (shadows: %#v, all: %#v)", len(shadows), shadows, snapshotJobs(&mu, jobs))
	}
	shadow := shadows[0]
	if shadow["topic"] != "job.openclaw.tool_call" {
		t.Fatalf("shadow topic = %#v, want job.openclaw.tool_call (shadow=%#v)", shadow["topic"], shadow)
	}
	labels, ok := shadow["labels"].(map[string]any)
	if !ok {
		t.Fatalf("shadow labels = %T, want object: %#v", shadow["labels"], shadow)
	}
	wantLabels := map[string]string{
		"cordclaw.shadow":         "true",
		"cordclaw.would_decision": "DENY",
		"cordclaw.rule_id":        "openclaw-shadow-strict-web-fetch",
		"cordclaw.hook_name":      "before_tool_execution",
	}
	for key, want := range wantLabels {
		if labels[key] != want {
			t.Fatalf("label %s = %#v, want %q (labels=%#v)", key, labels[key], want, labels)
		}
	}
	if labels["cordclaw.would_reason"] == "" {
		t.Fatalf("cordclaw.would_reason label missing: %#v", labels)
	}
}

func runCheckBurst(t *testing.T, h *Handler, agentID string, count int) map[string]int {
	t.Helper()
	return runCheckBurstRequest(t, h, CheckRequest{Tool: "exec", Command: "echo hi", AgentID: agentID}, count)
}

func runCheckBurstRequest(t *testing.T, h *Handler, payload CheckRequest, count int) map[string]int {
	t.Helper()
	out := map[string]int{}
	body, _ := json.Marshal(payload)
	for i := 0; i < count; i++ {
		req := httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.Router().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, body = %s", i, w.Code, w.Body.String())
		}
		var response PolicyResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("decode response %d: %v", i, err)
		}
		out[response.Decision]++
		if response.Reason == "rate_limited" {
			out["rate_limited"]++
		}
	}
	return out
}

func snapshotJobs(mu *sync.Mutex, jobs []map[string]any) []map[string]any {
	mu.Lock()
	defer mu.Unlock()
	out := make([]map[string]any, len(jobs))
	copy(out, jobs)
	return out
}

func summaryJobs(jobs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, job := range jobs {
		if job["topic"] == "job.openclaw.rate_limit_summary" {
			out = append(out, job)
		}
	}
	return out
}

func shadowJobs(jobs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, job := range jobs {
		labels, ok := job["labels"].(map[string]any)
		if !ok {
			continue
		}
		if labels["cordclaw.shadow"] == "true" {
			out = append(out, job)
		}
	}
	return out
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
