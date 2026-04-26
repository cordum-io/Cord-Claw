package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunnerReportsPolicyReplayDiffCounts(t *testing.T) {
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	apiKey := "test-api-key-do-not-print"
	var jobsCalled, replayCalled, auditCalled bool

	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit" {
			t.Fatalf("unexpected daemon path %s", r.URL.Path)
		}
		auditCalled = true
		if got := r.URL.Query().Get("limit"); got != "100" {
			t.Fatalf("audit limit = %q, want 100", got)
		}
		writeJSON(t, w, map[string]any{"decisions": fakeAuditEntries(100, now)})
	}))
	defer daemon.Close()

	cordum := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != apiKey {
			t.Fatalf("X-API-Key = %q, want supplied API key", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs":
			jobsCalled = true
			if got := r.URL.Query().Get("topic"); got != "" {
				t.Fatalf("topic filter = %q, want empty because Cordum job listing does not support wildcard topics", got)
			}
			writeJSON(t, w, map[string]any{"items": fakeJobs(100, now), "next_cursor": nil})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/policy/replay":
			replayCalled = true
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode replay request: %v", err)
			}
			if got := req["candidate_content"]; got != "rules:\n  - id: deny-openclaw\n" {
				t.Fatalf("candidate_content = %#v", got)
			}
			filters, ok := req["filters"].(map[string]any)
			if !ok || filters["topic_pattern"] != "job.openclaw.*" || filters["tenant"] != "default" {
				t.Fatalf("filters = %#v, want tenant/default + topic pattern", req["filters"])
			}
			writeJSON(t, w, fakeReplayResponse(100, 30))
		default:
			t.Fatalf("unexpected Cordum request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer cordum.Close()

	report, err := NewRunner(Options{
		Since:                  now.Add(-1 * time.Hour),
		Until:                  now,
		Tenant:                 "default",
		MaxJobs:                100,
		CandidatePolicyContent: "rules:\n  - id: deny-openclaw\n",
		DaemonURL:              daemon.URL,
		CordumURL:              cordum.URL,
		APIKey:                 apiKey,
	}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !auditCalled || !jobsCalled || !replayCalled {
		t.Fatalf("expected audit/jobs/replay calls, got audit=%v jobs=%v replay=%v", auditCalled, jobsCalled, replayCalled)
	}
	if report.Total != 100 || report.DecisionsUnchanged != 70 || report.WouldDeny != 30 || report.WouldRequireApproval != 0 || report.WouldConstrain != 0 {
		t.Fatalf("unexpected report counts: %+v", report)
	}
	if len(report.RuleHits) != 1 || report.RuleHits[0].RuleID != "deny-openclaw" || report.RuleHits[0].Count != 30 {
		t.Fatalf("unexpected rule hits: %+v", report.RuleHits)
	}
}

func TestReportJSONUsesStableMachineKeys(t *testing.T) {
	report := Report{
		Total:                3,
		DecisionsUnchanged:   1,
		WouldDeny:            1,
		WouldRequireApproval: 1,
		WouldConstrain:       0,
		SkippedAuditOnly:     2,
		RuleHits:             []RuleHit{{RuleID: "deny-openclaw", Decision: "DENY", Count: 1}},
		Warnings:             []string{"audit-only entries skipped"},
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json output invalid: %v", err)
	}
	for _, key := range []string{"total", "decisions_unchanged", "would_deny", "would_require_approval", "would_constrain", "skipped_audit_only", "rule_hits", "warnings"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("json output missing stable key %q: %s", key, buf.String())
		}
	}
}

func TestReportHumanOutputIncludesSummaryAndRuleHits(t *testing.T) {
	report := Report{Total: 100, DecisionsUnchanged: 70, WouldDeny: 30, RuleHits: []RuleHit{{RuleID: "deny-openclaw", Decision: "DENY", Count: 30}}}
	var buf bytes.Buffer
	if err := report.WriteHuman(&buf); err != nil {
		t.Fatalf("WriteHuman returned error: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"100 decisions", "70 unchanged", "30 would deny", "deny-openclaw", "DENY"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
}

func TestOptionsValidateRejectsInvalidSinceAndTooWideRange(t *testing.T) {
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	if err := (Options{Since: now.Add(-time.Hour), Until: now, CandidatePolicyContent: "rules: []", DaemonURL: "http://daemon", CordumURL: "http://cordum", APIKey: "k"}).Validate(); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	if err := (Options{Since: now, Until: now.Add(-time.Hour), CandidatePolicyContent: "rules: []", DaemonURL: "http://daemon", CordumURL: "http://cordum", APIKey: "k"}).Validate(); err == nil {
		t.Fatal("expected inverted time range to be rejected")
	}
	if err := (Options{Since: now.Add(-8 * 24 * time.Hour), Until: now, CandidatePolicyContent: "rules: []", DaemonURL: "http://daemon", CordumURL: "http://cordum", APIKey: "k"}).Validate(); err == nil {
		t.Fatal("expected >7d time range to be rejected")
	}
	if err := (Options{Since: now.Add(-time.Hour), Until: now, CandidatePolicyContent: "rules: []", DaemonURL: "http://daemon", CordumURL: "http://cordum", APIKey: "k", MaxJobs: 1001}).Validate(); err == nil {
		t.Fatal("expected max_jobs >1000 to be rejected")
	}
}

func TestRunnerWrapsHTTPAndJSONErrorsWithoutLeakingAPIKey(t *testing.T) {
	apiKey := "super-secret-api-key"
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"decisions": []any{}})
	}))
	defer daemon.Close()
	cordum := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/jobs":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
		default:
			_, _ = w.Write([]byte(`not-json`))
		}
	}))
	defer cordum.Close()

	_, err := NewRunner(Options{Since: now.Add(-time.Hour), Until: now, Tenant: "default", MaxJobs: 10, CandidatePolicyContent: "rules: []", DaemonURL: daemon.URL, CordumURL: cordum.URL, APIKey: apiKey}).Run(context.Background())
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	if strings.Contains(err.Error(), apiKey) {
		t.Fatalf("error leaked API key: %v", err)
	}
	if !strings.Contains(err.Error(), "jobs") {
		t.Fatalf("error should identify failing surface, got: %v", err)
	}
}

func TestRunnerCountsAuditOnlyEntriesAsSkipped(t *testing.T) {
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, map[string]any{"decisions": fakeAuditEntries(5, now)})
	}))
	defer daemon.Close()
	cordum := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/jobs":
			writeJSON(t, w, map[string]any{"items": []any{}, "next_cursor": nil})
		case "/api/v1/policy/replay":
			writeJSON(t, w, fakeReplayResponse(0, 0))
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer cordum.Close()

	report, err := NewRunner(Options{Since: now.Add(-time.Hour), Until: now, Tenant: "default", MaxJobs: 10, CandidatePolicyContent: "rules: []", DaemonURL: daemon.URL, CordumURL: cordum.URL, APIKey: "k"}).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if report.Total != 0 || report.SkippedAuditOnly != 5 {
		t.Fatalf("audit-only entries should be skipped, got total=%d skipped=%d", report.Total, report.SkippedAuditOnly)
	}
}

func fakeAuditEntries(n int, now time.Time) []map[string]any {
	entries := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, map[string]any{
			"timestamp": now.Add(-time.Duration(i) * time.Minute).Format(time.RFC3339Nano),
			"tool":      "exec",
			"decision":  "ALLOW",
			"reason":    "fixture",
			"details": map[string]any{
				"job_id": fmt.Sprintf("openclaw-%03d", i),
			},
		})
	}
	return entries
}

func fakeJobs(n int, now time.Time) []map[string]any {
	items := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, map[string]any{
			"id":              fmt.Sprintf("openclaw-%03d", i),
			"topic":           "job.openclaw.tool_call",
			"tenant":          "default",
			"updated_at":      now.Add(-time.Duration(i) * time.Minute).UnixMicro(),
			"safety_decision": "ALLOW",
		})
	}
	return items
}

func fakeReplayResponse(total, denied int) map[string]any {
	changes := make([]map[string]any, 0, denied)
	for i := 0; i < denied; i++ {
		changes = append(changes, map[string]any{
			"job_id":            fmt.Sprintf("openclaw-%03d", i),
			"topic":             "job.openclaw.tool_call",
			"tenant":            "default",
			"original_decision": "ALLOW",
			"new_decision":      "DENY",
			"new_rule_id":       "deny-openclaw",
			"new_reason":        "stricter policy",
			"direction":         "escalated",
		})
	}
	return map[string]any{
		"replay_id":       "replay-fixture",
		"policy_snapshot": "snapshot-fixture",
		"time_range":      map[string]any{"from": "2026-04-26T11:00:00Z", "to": "2026-04-26T12:00:00Z"},
		"summary": map[string]any{
			"total_jobs": total,
			"evaluated":  total,
			"escalated":  denied,
			"relaxed":    0,
			"unchanged":  total - denied,
			"errored":    0,
		},
		"rule_hits": []map[string]any{{"rule_id": "deny-openclaw", "decision": "DENY", "count": denied}},
		"changes":   changes,
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
}
