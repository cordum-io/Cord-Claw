package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
)

func newCordumJobsTestClient(t *testing.T, handler http.HandlerFunc) (SafetyClient, *httptest.Server) {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Setenv("CORDUM_API_KEY", "test-key")

	client, err := NewCordumJobsClient(config.Config{
		CordumGatewayURL: srv.URL,
		TenantID:         "tenant-a",
		CacheTTL:         time.Minute,
		CacheMaxSize:     32,
	}, cache.New(32))
	if err != nil {
		srv.Close()
		t.Fatalf("new cordum jobs client: %v", err)
	}
	return client, srv
}

func cordumJobsRequest() mapper.PolicyCheckRequest {
	return mapper.PolicyCheckRequest{
		HookName:        "before_tool_execution",
		Topic:           "job.openclaw.before_tool_execution",
		Capability:      "openclaw.before_tool_execution",
		Tool:            "web_fetch",
		HookType:        "before_tool_execution",
		URL:             "https://example.test/report",
		Agent:           "agent-1",
		Session:         "session-1",
		TurnOrigin:      "user",
		OpenClawVersion: "0.9.0-test",
		RiskTags:        []string{"network", "read"},
		Envelope: map[string]any{
			"tool": "web_fetch",
			"url":  "https://example.test/report",
		},
	}
}

func TestCordumJobsClientSubmitAllow(t *testing.T) {
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-1","trace_id":"trace-1","safety_decision":"ALLOW","safety_reason":"ok","safety_snapshot":"snap-1"}`))
	})
	defer srv.Close()

	decision, err := client.Check(context.Background(), cordumJobsRequest())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW", decision.Decision)
	}
	if decision.Reason != "ok" {
		t.Fatalf("reason = %q, want ok", decision.Reason)
	}
	if decision.Snapshot != "snap-1" {
		t.Fatalf("snapshot = %q, want snap-1", decision.Snapshot)
	}
}

func TestCordumJobsClientSubmitDeny(t *testing.T) {
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"job_id":"job-2","status":403,"safety_decision":"DENY","safety_reason":"blocked"}`))
	})
	defer srv.Close()

	decision, err := client.Check(context.Background(), cordumJobsRequest())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Decision != "DENY" {
		t.Fatalf("decision = %q, want DENY", decision.Decision)
	}
	if decision.Reason != "blocked" {
		t.Fatalf("reason = %q, want blocked", decision.Reason)
	}
}

func TestCordumJobsClientSubmitConstrain(t *testing.T) {
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-3","safety_decision":"CONSTRAIN","constraints":{"maxOutputBytes":262144}}`))
	})
	defer srv.Close()

	decision, err := client.Check(context.Background(), cordumJobsRequest())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Decision != "CONSTRAIN" {
		t.Fatalf("decision = %q, want CONSTRAIN", decision.Decision)
	}
	if decision.Constraints["maxOutputBytes"] != float64(262144) {
		t.Fatalf("maxOutputBytes = %#v, want 262144", decision.Constraints["maxOutputBytes"])
	}
}

func TestCordumJobsClientSubmitRequireHuman(t *testing.T) {
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-4","status":"approval_required","safety_decision":"REQUIRE_HUMAN","approval_ref":"appr-7"}`))
	})
	defer srv.Close()

	decision, err := client.Check(context.Background(), cordumJobsRequest())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if decision.Decision != "REQUIRE_HUMAN" {
		t.Fatalf("decision = %q, want REQUIRE_HUMAN", decision.Decision)
	}
	if decision.ApprovalRef != "appr-7" {
		t.Fatalf("approvalRef = %q, want appr-7", decision.ApprovalRef)
	}
}

func TestCordumJobsClientSubmitHTTP500(t *testing.T) {
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	})
	defer srv.Close()

	_, err := client.Check(context.Background(), cordumJobsRequest())
	if err == nil {
		t.Fatalf("error = nil, want wrapped status error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %q, want status 500", err.Error())
	}
}

func TestCordumJobsClientSubmitMissingSafetyDecisionFailsClosed(t *testing.T) {
	var hits atomic.Int32
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"job_id":"job-replayed","trace_id":"trace-replayed"}`))
	})
	defer srv.Close()

	decision, err := client.Check(context.Background(), cordumJobsRequest())
	if err == nil {
		t.Fatalf("error = nil, want fail-closed missing safety_decision error")
	}
	if !strings.Contains(err.Error(), "missing safety_decision") {
		t.Fatalf("error = %q, want missing safety_decision", err.Error())
	}
	if decision.Decision == "ALLOW" {
		t.Fatalf("decision = ALLOW, want no silent allow on 2xx response without safety_decision")
	}

	_, err = client.Check(context.Background(), cordumJobsRequest())
	if err == nil {
		t.Fatalf("second error = nil, want missing safety_decision to remain uncached and fail closed")
	}
	if hits.Load() != 2 {
		t.Fatalf("http hits = %d, want 2 because missing safety_decision must not be cached", hits.Load())
	}
}

func TestCordumJobsClientSubmitTimeout(t *testing.T) {
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	_, err := client.Check(ctx, cordumJobsRequest())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want context deadline exceeded", err)
	}
}

func TestCordumJobsClientSubmitAuthHeader(t *testing.T) {
	var got string
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-API-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safety_decision":"ALLOW"}`))
	})
	defer srv.Close()

	if _, err := client.Check(context.Background(), cordumJobsRequest()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if got != "test-key" {
		t.Fatalf("X-API-Key = %q, want test-key", got)
	}
}

func TestCordumJobsClientRequestShapeMatchesGatewayContract(t *testing.T) {
	var body map[string]any
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safety_decision":"ALLOW"}`))
	})
	defer srv.Close()

	req := cordumJobsRequest()
	if _, err := client.Check(context.Background(), req); err != nil {
		t.Fatalf("check: %v", err)
	}

	if body["topic"] != "job.openclaw.before_tool_execution" {
		t.Fatalf("topic = %#v, want job.openclaw.before_tool_execution", body["topic"])
	}
	if body["pack_id"] != "cordclaw" {
		t.Fatalf("pack_id = %#v, want cordclaw", body["pack_id"])
	}
	if body["tenant_id"] != "tenant-a" {
		t.Fatalf("tenant_id = %#v, want tenant-a", body["tenant_id"])
	}
	if body["org_id"] != "tenant-a" {
		t.Fatalf("org_id = %#v, want tenant-a", body["org_id"])
	}
	if body["principal_id"] != "agent-1" {
		t.Fatalf("principal_id = %#v, want agent-1", body["principal_id"])
	}
	if body["actor_id"] != "agent-1" {
		t.Fatalf("actor_id = %#v, want agent-1", body["actor_id"])
	}
	if body["actor_type"] != "service" {
		t.Fatalf("actor_type = %#v, want service", body["actor_type"])
	}
	if body["capability"] != "openclaw.before_tool_execution" {
		t.Fatalf("capability = %#v, want openclaw.before_tool_execution", body["capability"])
	}
	if body["idempotency_key"] == "" {
		t.Fatalf("idempotency_key = empty, want payload hash")
	}
	riskTags, ok := body["risk_tags"].([]any)
	if !ok || len(riskTags) != 2 || riskTags[0] != "network" || riskTags[1] != "read" {
		t.Fatalf("risk_tags = %#v, want [network read]", body["risk_tags"])
	}
	labels, ok := body["labels"].(map[string]any)
	if !ok {
		t.Fatalf("labels = %T, want object", body["labels"])
	}
	for key, want := range map[string]string{
		"cordclaw.hook":             "before_tool_execution",
		"cordclaw.session":          "session-1",
		"cordclaw.turn_origin":      "user",
		"cordclaw.openclaw_version": "0.9.0-test",
	} {
		if labels[key] != want {
			t.Fatalf("labels[%s] = %#v, want %q", key, labels[key], want)
		}
	}
	contextObj, ok := body["context"].(map[string]any)
	if !ok {
		t.Fatalf("context = %T, want object", body["context"])
	}
	if contextObj["url"] != "https://example.test/report" {
		t.Fatalf("context.url = %#v, want envelope URL", contextObj["url"])
	}
	if _, hasMeta := body["meta"]; hasMeta {
		t.Fatalf("request must use actual /api/v1/jobs contract (top-level capability + context), got stale meta object: %#v", body["meta"])
	}
}

func TestCordumJobsClientCacheHitSkipsSecondHTTPPost(t *testing.T) {
	var hits atomic.Int32
	client, srv := newCordumJobsTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"safety_decision":"ALLOW","safety_snapshot":"snap-cache"}`))
	})
	defer srv.Close()

	req := cordumJobsRequest()
	first, err := client.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("first check: %v", err)
	}
	second, err := client.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("second check: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("http hits = %d, want 1", hits.Load())
	}
	if first.Decision != second.Decision || second.Snapshot != "snap-cache" {
		t.Fatalf("cached decision = %#v, want same ALLOW snap-cache decision as first %#v", second, first)
	}
	t.Logf("cache-hit evidence: http_hits=%d first=%s second=%s snapshot=%s", hits.Load(), first.Decision, second.Decision, second.Snapshot)
}
