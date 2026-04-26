package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

type failingCronDecisionStore struct {
	err  error
	puts int
	gets int
}

func (s *failingCronDecisionStore) Put(string, policy.CronDecisionRecord) error {
	s.puts++
	return s.err
}
func (s *failingCronDecisionStore) Get(string) (policy.CronDecisionRecord, bool, error) {
	s.gets++
	return policy.CronDecisionRecord{}, false, s.err
}
func (s *failingCronDecisionStore) Delete(string) error { return s.err }
func (s *failingCronDecisionStore) Close() error        { return nil }

func TestNewWithErrorSurfacesCronDecisionStoreOpenError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cron-decisions.db")
	if err := os.WriteFile(path, []byte("not a bolt database"), 0o600); err != nil {
		t.Fatalf("write corrupt store: %v", err)
	}

	_, err := NewWithError(config.Config{
		CacheMaxSize:      100,
		CacheTTL:          5 * time.Minute,
		FailMode:          "closed",
		CronDecisionStore: "bolt",
		CronDecisionPath:  path,
		CronDecisionTTL:   24 * time.Hour,
	}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	if err == nil {
		t.Fatalf("expected corrupt cron decision store to fail handler startup")
	}
}

func TestHandlerCloseReleasesCronDecisionStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cron-decisions.db")
	h, err := NewWithError(config.Config{
		CacheMaxSize:      100,
		CacheTTL:          5 * time.Minute,
		FailMode:          "closed",
		CronDecisionStore: "bolt",
		CronDecisionPath:  path,
		CronDecisionTTL:   24 * time.Hour,
	}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("close handler: %v", err)
	}

	h2, err := NewWithError(config.Config{
		CacheMaxSize:      100,
		CacheTTL:          5 * time.Minute,
		FailMode:          "closed",
		CronDecisionStore: "bolt",
		CronDecisionPath:  path,
		CronDecisionTTL:   24 * time.Hour,
	}, &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})
	if err != nil {
		t.Fatalf("reopen after handler close: %v", err)
	}
	defer h2.Close()
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

func TestCheckCronCreateAllowSurvivesBoltRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cron-decisions.db")
	secretPrompt := "cron prompt sk-CRON-SECRET-DONTLEAK"
	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldWriter)

	safetyA := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	hA := newBoltCronHandlerForTest(t, path, 24*time.Hour, safetyA)
	cronResponse := serveCheckForTest(t, hA, CheckRequest{
		Tool:       "cron.create",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "session-parent",
		PromptText: secretPrompt,
	})
	if cronResponse.Decision != "ALLOW" {
		t.Fatalf("cron_create decision = %q, want ALLOW", cronResponse.Decision)
	}
	if err := hA.Close(); err != nil {
		t.Fatalf("close first handler: %v", err)
	}

	safetyB := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-2"}}
	hB := newBoltCronHandlerForTest(t, path, 24*time.Hour, safetyB)
	defer hB.Close()
	agentResponse := serveCheckForTest(t, hB, CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "cron",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "cron:cron-7",
		PromptText: secretPrompt,
	})
	if agentResponse.Decision != "ALLOW" {
		t.Fatalf("agent_start decision = %q, want ALLOW", agentResponse.Decision)
	}
	if len(safetyB.requests) != 1 {
		t.Fatalf("safety requests after restart = %d, want 1", len(safetyB.requests))
	}
	if containsString(safetyB.requests[0].RiskTags, "cron_fire") {
		t.Fatalf("known cron safety request retained cron_fire: %v", safetyB.requests[0].RiskTags)
	}
	if !containsString(safetyB.requests[0].RiskTags, "cron_origin_verified") {
		t.Fatalf("known cron safety request missing cron_origin_verified: %v", safetyB.requests[0].RiskTags)
	}
	assertNoCronSecretLeak(t, secretPrompt, logBuf.String(), hA.auditLog, hB.auditLog)
}

func TestCheckCronOriginEvictionDeniesAndStaysAbsent(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cron-decisions.db")

	safetyA := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	hA := newBoltCronHandlerForTest(t, path, 24*time.Hour, safetyA)
	hA.cronLog.SetNowFn(func() time.Time { return now })
	serveCheckForTest(t, hA, CheckRequest{Tool: "cron.create", CronJobID: "cron-7", Agent: "agent-1", Session: "session-parent"})
	if err := hA.Close(); err != nil {
		t.Fatalf("close first handler: %v", err)
	}

	safetyB := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-2"}}
	hB := newBoltCronHandlerForTest(t, path, 24*time.Hour, safetyB)
	hB.cronLog.SetNowFn(func() time.Time { return now.Add(24*time.Hour + time.Nanosecond) })
	response := serveCheckForTest(t, hB, CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "cron",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "cron:cron-7",
	})
	if response.Decision != "DENY" || response.Reason != "cron-origin-policy-mismatch" {
		t.Fatalf("expired cron response = %s/%q, want DENY/cron-origin-policy-mismatch", response.Decision, response.Reason)
	}
	if len(safetyB.requests) != 0 {
		t.Fatalf("expected expired cron deny before safety, got %d safety calls", len(safetyB.requests))
	}
	if err := hB.Close(); err != nil {
		t.Fatalf("close eviction handler: %v", err)
	}

	safetyC := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-3"}}
	hC := newBoltCronHandlerForTest(t, path, 24*time.Hour, safetyC)
	defer hC.Close()
	hC.cronLog.SetNowFn(func() time.Time { return now })
	response = serveCheckForTest(t, hC, CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "cron",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "cron:cron-7",
	})
	if response.Decision != "DENY" || response.Reason != "cron-origin-policy-mismatch" {
		t.Fatalf("evicted cron response = %s/%q, want DENY/cron-origin-policy-mismatch", response.Decision, response.Reason)
	}
	if len(safetyC.requests) != 0 {
		t.Fatalf("expected evicted cron deny before safety, got %d safety calls", len(safetyC.requests))
	}
}

func TestCheckAgentStartUnknownCronDeniesBeforeSafety(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed", LogDecisions: true}, safety)
	secretPrompt := "cron prompt sk-UNKNOWN-SECRET-DONTLEAK"

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
		PromptText: secretPrompt,
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
	assertNoCronSecretLeak(t, secretPrompt, logBuf.String(), h.auditLog)
}

func TestCheckAgentStartCronStoreErrorDeniesBeforeSafety(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed", LogDecisions: true}, safety)
	failingStore := &failingCronDecisionStore{err: errors.New("bolt read unavailable")}
	h.cronLog = policy.NewCronDecisionLogWithStore(24*time.Hour, failingStore)
	secretPrompt := "cron prompt sk-STORE-SECRET-DONTLEAK"

	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldWriter)

	response := serveCheckForTest(t, h, CheckRequest{
		Tool:       "agent_start",
		Hook:       "before_agent_start",
		HookType:   "before_agent_start",
		TurnOrigin: "cron",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "cron:cron-7",
		PromptText: secretPrompt,
	})
	if response.Decision != "DENY" || response.Reason != "cron-origin-policy-mismatch" {
		t.Fatalf("store-error cron response = %s/%q, want DENY/cron-origin-policy-mismatch", response.Decision, response.Reason)
	}
	if failingStore.gets != 1 {
		t.Fatalf("store lookups = %d, want 1", failingStore.gets)
	}
	if len(safety.requests) != 0 {
		t.Fatalf("expected store-error cron deny before safety, got %d safety calls", len(safety.requests))
	}
	assertNoCronSecretLeak(t, secretPrompt, logBuf.String(), h.auditLog)
}

func TestCheckCronCreateStoreErrorLogsWithoutPromptLeak(t *testing.T) {
	safety := &fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}}
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "closed", LogDecisions: true}, safety)
	failingStore := &failingCronDecisionStore{err: errors.New("bolt write unavailable")}
	h.cronLog = policy.NewCronDecisionLogWithStore(24*time.Hour, failingStore)
	secretPrompt := "cron prompt sk-WRITE-SECRET-DONTLEAK"

	var logBuf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(oldWriter)

	response := serveCheckForTest(t, h, CheckRequest{
		Tool:       "cron.create",
		CronJobID:  "cron-7",
		Agent:      "agent-1",
		Session:    "session-parent",
		PromptText: secretPrompt,
	})
	if response.Decision != "ALLOW" {
		t.Fatalf("cron_create decision = %q, want ALLOW from safety", response.Decision)
	}
	if failingStore.puts != 1 {
		t.Fatalf("store writes = %d, want 1", failingStore.puts)
	}
	if !strings.Contains(logBuf.String(), "cron decision record failed") {
		t.Fatalf("missing store write failure log: %s", logBuf.String())
	}
	assertNoCronSecretLeak(t, secretPrompt, logBuf.String(), h.auditLog)
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

func newBoltCronHandlerForTest(t *testing.T, path string, ttl time.Duration, safety *fakeSafety) *Handler {
	t.Helper()
	h, err := NewWithError(config.Config{
		CacheMaxSize:      100,
		CacheTTL:          5 * time.Minute,
		FailMode:          "closed",
		LogDecisions:      true,
		CronDecisionStore: "bolt",
		CronDecisionPath:  path,
		CronDecisionTTL:   ttl,
	}, safety)
	if err != nil {
		t.Fatalf("NewWithError: %v", err)
	}
	return h
}

func serveCheckForTest(t *testing.T, h *Handler, payload CheckRequest) PolicyResponse {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
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
	return response
}

func assertNoCronSecretLeak(t *testing.T, secret string, logOutput string, auditLogs ...[]AuditEntry) {
	t.Helper()
	if strings.Contains(logOutput, secret) {
		t.Fatalf("log output leaked cron prompt/secret: %s", logOutput)
	}
	for _, auditLog := range auditLogs {
		encoded, err := json.Marshal(auditLog)
		if err != nil {
			t.Fatalf("marshal audit log: %v", err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("audit log leaked cron prompt/secret: %s", encoded)
		}
		if strings.Contains(string(encoded), "prompt_text") || strings.Contains(string(encoded), "description") {
			t.Fatalf("audit log included cron prompt/description fields: %s", encoded)
		}
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
