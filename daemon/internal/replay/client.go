package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type auditResponse struct {
	Decisions []auditEntry `json:"decisions"`
}

type auditEntry struct {
	Timestamp string         `json:"timestamp"`
	Tool      string         `json:"tool,omitempty"`
	Decision  string         `json:"decision,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Cached    bool           `json:"cached,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type jobsResponse struct {
	Items      []jobItem `json:"items"`
	NextCursor *int64    `json:"next_cursor"`
}

type jobItem struct {
	ID             string `json:"id"`
	Topic          string `json:"topic"`
	Tenant         string `json:"tenant"`
	UpdatedAt      int64  `json:"updated_at"`
	SafetyDecision string `json:"safety_decision"`
}

type policyReplayRequest struct {
	From             string             `json:"from"`
	To               string             `json:"to"`
	Filters          policyReplayFilter `json:"filters"`
	CandidateContent string             `json:"candidate_content"`
	MaxJobs          int                `json:"max_jobs"`
}

type policyReplayFilter struct {
	Tenant       string `json:"tenant,omitempty"`
	TopicPattern string `json:"topic_pattern,omitempty"`
}

type policyReplayResponse struct {
	ReplayID       string              `json:"replay_id"`
	PolicySnapshot string              `json:"policy_snapshot"`
	Summary        policyReplaySummary `json:"summary"`
	RuleHits       []RuleHit           `json:"rule_hits"`
	Changes        []Change            `json:"changes"`
	Warnings       []string            `json:"warnings,omitempty"`
	Errors         []string            `json:"errors,omitempty"`
}

type policyReplaySummary struct {
	TotalJobs int `json:"total_jobs"`
	Evaluated int `json:"evaluated"`
	Escalated int `json:"escalated"`
	Relaxed   int `json:"relaxed"`
	Unchanged int `json:"unchanged"`
	Errored   int `json:"errored"`
}

func (r *Runner) fetchAudit(ctx context.Context) (auditResponse, error) {
	values := url.Values{}
	values.Set("limit", strconv.Itoa(r.options.MaxJobs))
	endpoint := strings.TrimRight(r.options.DaemonURL, "/") + "/audit?" + values.Encode()
	var out auditResponse
	if err := r.getJSON(ctx, endpoint, "daemon audit", false, &out); err != nil {
		return auditResponse{}, err
	}
	return out, nil
}

func (r *Runner) fetchJobs(ctx context.Context) (jobsResponse, error) {
	values := url.Values{}
	values.Set("tenant", r.options.Tenant)
	values.Set("updated_after", strconv.FormatInt(r.options.Since.UTC().UnixMicro(), 10))
	values.Set("updated_before", strconv.FormatInt(r.options.Until.UTC().UnixMicro(), 10))
	values.Set("limit", strconv.Itoa(r.options.MaxJobs))
	endpoint := strings.TrimRight(r.options.CordumURL, "/") + "/api/v1/jobs?" + values.Encode()
	var out jobsResponse
	if err := r.getJSON(ctx, endpoint, "jobs", true, &out); err != nil {
		return jobsResponse{}, err
	}
	filtered := out.Items[:0]
	for _, item := range out.Items {
		if strings.HasPrefix(item.Topic, "job.openclaw.") {
			filtered = append(filtered, item)
		}
	}
	out.Items = filtered
	return out, nil
}

func (r *Runner) runPolicyReplay(ctx context.Context, candidate string) (policyReplayResponse, error) {
	body := policyReplayRequest{
		From: r.options.Since.UTC().Format(timeRFC3339),
		To:   r.options.Until.UTC().Format(timeRFC3339),
		Filters: policyReplayFilter{
			Tenant:       r.options.Tenant,
			TopicPattern: "job.openclaw.*",
		},
		CandidateContent: candidate,
		MaxJobs:          r.options.MaxJobs,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return policyReplayResponse{}, fmt.Errorf("policy replay request: %w", err)
	}
	endpoint := strings.TrimRight(r.options.CordumURL, "/") + "/api/v1/policy/replay"
	var out policyReplayResponse
	if err := r.doJSON(ctx, http.MethodPost, endpoint, "policy replay", true, bytes.NewReader(payload), &out); err != nil {
		return policyReplayResponse{}, err
	}
	return out, nil
}

const timeRFC3339 = "2006-01-02T15:04:05Z07:00"

func (r *Runner) getJSON(ctx context.Context, endpoint, surface string, auth bool, out any) error {
	return r.doJSON(ctx, http.MethodGet, endpoint, surface, auth, nil, out)
}

func (r *Runner) doJSON(ctx context.Context, method, endpoint, surface string, auth bool, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return fmt.Errorf("%s request: %w", surface, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth && strings.TrimSpace(r.options.APIKey) != "" {
		req.Header.Set("X-API-Key", r.options.APIKey)
		req.Header.Set("Authorization", "Bearer "+r.options.APIKey)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", surface, err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxBodyBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("%s read response: %w", surface, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d: %s", surface, resp.StatusCode, r.redact(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s decode response: %w", surface, err)
	}
	return nil
}

func (r *Runner) redact(s string) string {
	key := strings.TrimSpace(r.options.APIKey)
	if key == "" {
		return s
	}
	return strings.ReplaceAll(s, key, "[REDACTED:api_key]")
}
