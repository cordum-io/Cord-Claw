package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReplayCommandHumanOutputAgainstFakeGateway(t *testing.T) {
	apiKey := "cli-test-api-key-never-print"
	daemon, cordum := newReplayFixtureServers(t, apiKey, 100, 100, 30)
	defer daemon.Close()
	defer cordum.Close()

	policyPath := writeTempPolicy(t)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := run([]string{
		"replay",
		"--since", "1h",
		"--with-policy", policyPath,
		"--daemon-url", daemon.URL,
		"--cordum-url", cordum.URL,
		"--tenant", "default",
		"--max-jobs", "100",
	}, envMap(map[string]string{"CORDUM_API_KEY": apiKey}), stdout, stderr)
	if code != 0 {
		t.Fatalf("run returned code %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"100 decisions replayed", "70 unchanged", "30 would deny", "0 would require approval", "0 would constrain", "deny-openclaw", "Top rule hits"} {
		if !strings.Contains(out, want) {
			t.Fatalf("human output missing %q:\n%s", want, out)
		}
	}
	assertNoSecret(t, apiKey, out, stderr.String())
}

func TestReplayCommandJSONOutputAgainstFakeGateway(t *testing.T) {
	apiKey := "cli-json-api-key-never-print"
	daemon, cordum := newReplayFixtureServers(t, apiKey, 100, 100, 30)
	defer daemon.Close()
	defer cordum.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := run([]string{
		"replay",
		"--since", "2h",
		"--with-policy", writeTempPolicy(t),
		"--daemon-url", daemon.URL,
		"--cordum-url", cordum.URL,
		"--max-jobs", "100",
		"--json",
	}, envMap(map[string]string{"CORDUM_API_KEY": apiKey}), stdout, stderr)
	if code != 0 {
		t.Fatalf("run returned code %d, stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}

	var got struct {
		Total                int `json:"total"`
		DecisionsUnchanged   int `json:"decisions_unchanged"`
		WouldDeny            int `json:"would_deny"`
		WouldRequireApproval int `json:"would_require_approval"`
		WouldConstrain       int `json:"would_constrain"`
		SkippedAuditOnly     int `json:"skipped_audit_only"`
		RuleHits             []struct {
			RuleID string `json:"rule_id"`
			Count  int    `json:"count"`
		} `json:"rule_hits"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("json output invalid: %v\n%s", err, stdout.String())
	}
	if got.Total != 100 || got.DecisionsUnchanged != 70 || got.WouldDeny != 30 || got.WouldRequireApproval != 0 || got.WouldConstrain != 0 || got.SkippedAuditOnly != 0 {
		t.Fatalf("unexpected json counts: %+v", got)
	}
	if len(got.RuleHits) != 1 || got.RuleHits[0].RuleID != "deny-openclaw" || got.RuleHits[0].Count != 30 {
		t.Fatalf("unexpected rule hits: %+v", got.RuleHits)
	}
	assertNoSecret(t, apiKey, stdout.String(), stderr.String())
}

func TestReplayCommandReportsAuditOnlyWhenCordumHasNoJobs(t *testing.T) {
	apiKey := "cli-zero-jobs-key-never-print"
	daemon, cordum := newReplayFixtureServers(t, apiKey, 4, 0, 0)
	defer daemon.Close()
	defer cordum.Close()

	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	code := run([]string{
		"replay",
		"--since", "30m",
		"--with-policy", writeTempPolicy(t),
		"--daemon-url", daemon.URL,
		"--cordum-url", cordum.URL,
	}, envMap(map[string]string{"CORDUM_API_KEY": apiKey}), stdout, stderr)
	if code != 0 {
		t.Fatalf("run returned code %d, stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"0 decisions replayed", "4 skipped audit-only", "Warnings", "4 audit-only entries skipped"} {
		if !strings.Contains(out, want) {
			t.Fatalf("zero-job output missing %q:\n%s", want, out)
		}
	}
	assertNoSecret(t, apiKey, out, stderr.String())
}

func newReplayFixtureServers(t *testing.T, apiKey string, auditCount, jobCount, denied int) (*httptest.Server, *httptest.Server) {
	t.Helper()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/audit" {
			t.Errorf("unexpected daemon request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("limit"); got == "" {
			t.Errorf("audit request missing limit")
		}
		writeJSON(t, w, map[string]any{"decisions": fakeAuditEntries(auditCount, now)})
	}))

	cordum := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-API-Key"); got != apiKey {
			t.Errorf("X-API-Key = %q, want supplied API key", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs":
			if got := r.URL.Query().Get("tenant"); got != "default" {
				t.Errorf("tenant = %q, want default", got)
			}
			writeJSON(t, w, map[string]any{"items": fakeJobs(jobCount, now), "next_cursor": nil})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/policy/replay":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("decode replay request: %v", err)
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			if strings.TrimSpace(fmt.Sprint(req["candidate_content"])) == "" {
				t.Errorf("candidate_content should be populated")
			}
			writeJSON(t, w, fakeReplayResponse(jobCount, denied))
		default:
			t.Errorf("unexpected Cordum request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	return daemon, cordum
}

func writeTempPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "candidate-policy.yaml")
	content := []byte("version: \"1\"\nrules:\n  - id: deny-openclaw\n    decision: deny\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write temp policy: %v", err)
	}
	return path
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
		"replay_id":       "cli-replay-fixture",
		"policy_snapshot": "snapshot-fixture",
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

func envMap(values map[string]string) getenvFunc {
	return func(key string) string { return values[key] }
}

func assertNoSecret(t *testing.T, secret string, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(value, secret) {
			t.Fatalf("output leaked API key %q in %q", secret, value)
		}
	}
}
