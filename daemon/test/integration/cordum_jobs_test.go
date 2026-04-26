//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/server"
)

func bootDaemonWithGateway(t *testing.T, gatewayURL string) *httptest.Server {
	t.Helper()

	t.Setenv("CORDCLAW_CORDUM_GATEWAY_URL", gatewayURL)
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_API_KEY", "legacy-key-should-not-win")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")
	t.Setenv("CORDCLAW_KERNEL_ADDR", "")
	t.Setenv("CORDCLAW_FAIL_MODE", "graduated")
	t.Setenv("CORDCLAW_CACHE_TTL", "5m")
	t.Setenv("CORDCLAW_CACHE_MAX_SIZE", "100")

	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	handler := server.New(cfg, nil)
	t.Cleanup(func() {
		if err := handler.Close(); err != nil {
			t.Fatalf("handler close: %v", err)
		}
	})
	return httptest.NewServer(handler.Router())
}

func TestCordumJobs_Integration_GatedAction(t *testing.T) {
	var hits atomic.Int32
	var seenKey string
	var received map[string]any
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`ok`))
			return
		}
		if r.URL.Path != "/api/v1/jobs" {
			t.Fatalf("gateway path = %q, want /api/v1/jobs", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("gateway method = %q, want POST", r.Method)
		}
		hits.Add(1)
		seenKey = r.Header.Get("X-API-Key")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode submit body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-1","trace_id":"trace-1","safety_decision":"ALLOW","safety_reason":"ok","safety_snapshot":"snap-1","constraints":null,"approval_ref":""}`))
	}))
	defer gateway.Close()

	daemon := bootDaemonWithGateway(t, gateway.URL)
	defer daemon.Close()

	payload := map[string]any{
		"tool":             "web_fetch",
		"hook":             "before_tool_execution",
		"hookType":         "before_tool_execution",
		"url":              "https://example.test/report",
		"agent":            "test-agent",
		"session":          "s1",
		"turnOrigin":       "user",
		"openclawVersion":  "0.9.0-test",
		"openclaw_version": "0.9.0-test",
		"envelope": map[string]any{
			"tool": "web_fetch",
			"url":  "https://example.test/report",
		},
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(daemon.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post /check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/check status = %d, want 200", resp.StatusCode)
	}
	var policyResp server.PolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policyResp); err != nil {
		t.Fatalf("decode /check response: %v", err)
	}
	if policyResp.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW", policyResp.Decision)
	}
	if hits.Load() != 1 {
		t.Fatalf("gateway hits = %d, want 1", hits.Load())
	}
	if seenKey != "test-key" {
		t.Fatalf("X-API-Key = %q, want CORDUM_API_KEY test-key", seenKey)
	}
	if received["topic"] != "job.openclaw.before_tool_execution" {
		t.Fatalf("topic = %#v, want job.openclaw.before_tool_execution", received["topic"])
	}
	if received["pack_id"] != "cordclaw" {
		t.Fatalf("pack_id = %#v, want cordclaw", received["pack_id"])
	}
	if received["tenant_id"] != "tenant-a" || received["org_id"] != "tenant-a" {
		t.Fatalf("tenant fields = tenant_id:%#v org_id:%#v, want tenant-a", received["tenant_id"], received["org_id"])
	}
	if received["principal_id"] != "test-agent" || received["actor_id"] != "test-agent" {
		t.Fatalf("agent fields = principal_id:%#v actor_id:%#v, want test-agent", received["principal_id"], received["actor_id"])
	}
	labels, ok := received["labels"].(map[string]any)
	if !ok {
		t.Fatalf("labels = %T, want object", received["labels"])
	}
	if labels["cordclaw.hook"] != "before_tool_execution" {
		t.Fatalf("cordclaw.hook = %#v, want before_tool_execution", labels["cordclaw.hook"])
	}
	if labels["cordclaw.session"] != "s1" {
		t.Fatalf("cordclaw.session = %#v, want s1", labels["cordclaw.session"])
	}
	if labels["cordclaw.turn_origin"] != "user" {
		t.Fatalf("cordclaw.turn_origin = %#v, want user", labels["cordclaw.turn_origin"])
	}
	if labels["cordclaw.openclaw_version"] != "0.9.0-test" {
		t.Fatalf("cordclaw.openclaw_version = %#v, want 0.9.0-test", labels["cordclaw.openclaw_version"])
	}
	contextObj, ok := received["context"].(map[string]any)
	if !ok {
		t.Fatalf("context = %T, want object", received["context"])
	}
	if contextObj["url"] != "https://example.test/report" {
		t.Fatalf("context.url = %#v, want https://example.test/report", contextObj["url"])
	}
	t.Logf("fixture received topic=%s safety_decision=%s x_api_key=%s", received["topic"], policyResp.Decision, seenKey)
}

func TestCordumJobs_Integration_FailModeGraduated(t *testing.T) {
	var hits atomic.Int32
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer gateway.Close()

	daemon := bootDaemonWithGateway(t, gateway.URL)
	defer daemon.Close()

	payload := map[string]any{
		"tool":    "web_fetch",
		"hook":    "before_tool_execution",
		"url":     "https://example.test/report",
		"agent":   "test-agent",
		"session": "s1",
	}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(daemon.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post /check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/check status = %d, want 200", resp.StatusCode)
	}
	var policyResp server.PolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policyResp); err != nil {
		t.Fatalf("decode /check response: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("gateway hits = %d, want 1", hits.Load())
	}
	if policyResp.Decision != "DENY" {
		t.Fatalf("decision = %q, want DENY for graduated fail mode without cache", policyResp.Decision)
	}
	if policyResp.GovernanceStatus != "degraded" {
		t.Fatalf("governanceStatus = %q, want degraded", policyResp.GovernanceStatus)
	}
	if policyResp.Reason != "Governance degraded and no cached policy decision available" {
		t.Fatalf("reason = %q, want graduated fail-mode reason", policyResp.Reason)
	}
	t.Logf("graduated fail-mode evidence: fixture_hits=%d decision=%s status=%s", hits.Load(), policyResp.Decision, policyResp.GovernanceStatus)
}
