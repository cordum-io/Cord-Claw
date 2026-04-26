package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
)

const defaultCordumJobsTimeout = 5 * time.Second

type CordumJobsClient struct {
	baseURL    string
	apiKey     string
	tenantID   string
	httpClient *http.Client
	cache      *cache.LRU
	cacheTTL   time.Duration
}

func NewCordumJobsClient(cfg config.Config, c *cache.LRU) (SafetyClient, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.CordumGatewayURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("CORDCLAW_CORDUM_GATEWAY_URL is required")
	}

	apiKey := strings.TrimSpace(os.Getenv("CORDUM_API_KEY"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(cfg.CordumAPIKey)
	}
	if apiKey == "" {
		apiKey = strings.TrimSpace(cfg.APIKey)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("CORDUM_API_KEY or CORDCLAW_API_KEY is required")
	}

	if c == nil {
		c = cache.New(cfg.CacheMaxSize)
	}

	return &CordumJobsClient{
		baseURL:  baseURL,
		apiKey:   apiKey,
		tenantID: normalizeTenant(cfg.TenantID),
		httpClient: &http.Client{
			Timeout: defaultCordumJobsTimeout,
		},
		cache:    c,
		cacheTTL: cfg.CacheTTL,
	}, nil
}

func (c *CordumJobsClient) Check(ctx context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error) {
	return c.Submit(ctx, req)
}

func (c *CordumJobsClient) Submit(ctx context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || c.httpClient == nil {
		return cache.Decision{}, fmt.Errorf("cordum jobs client not initialized")
	}

	payloadHash, err := payloadHash(req, c.tenantID)
	if err != nil {
		return cache.Decision{}, fmt.Errorf("hash policy request: %w", err)
	}
	hook := normalizeHook(req)
	cacheKey := cache.KeyForHook(hook, req.Tool, payloadHash)
	if c.cache != nil {
		if decision, ok := c.cache.Get(cacheKey); ok {
			return decision, nil
		}
	}

	body, err := json.Marshal(c.jobSubmitRequest(req, hook, payloadHash))
	if err != nil {
		return cache.Decision{}, fmt.Errorf("marshal cordum job submit request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/jobs", bytes.NewReader(body))
	if err != nil {
		return cache.Decision{}, fmt.Errorf("build cordum job submit request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return cache.Decision{}, fmt.Errorf("submit cordum job: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return cache.Decision{}, fmt.Errorf("read cordum job submit response: %w", err)
	}
	decision, hasDecision, err := decisionFromJobsResponse(raw)
	if err != nil {
		return cache.Decision{}, fmt.Errorf("decode cordum job submit response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if hasDecision {
			if c.cache != nil {
				c.cache.Set(cacheKey, decision, c.cacheTTL)
			}
			return decision, nil
		}
		return cache.Decision{}, fmt.Errorf("cordum job submit status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !hasDecision {
		decision = cache.Decision{Decision: "ALLOW"}
	}
	if c.cache != nil {
		c.cache.Set(cacheKey, decision, c.cacheTTL)
	}
	return decision, nil
}

func (c *CordumJobsClient) Health(ctx context.Context) Health {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || c.httpClient == nil || c.baseURL == "" {
		return Health{Connected: false, State: "uninitialized"}
	}
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(checkCtx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return Health{Connected: false, State: "invalid"}
	}
	req.Header.Set("X-API-Key", c.apiKey)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Health{Connected: false, State: "unreachable"}
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Health{Connected: false, State: fmt.Sprintf("http_%d", resp.StatusCode)}
	}
	return Health{Connected: true, State: "ready"}
}

func (c *CordumJobsClient) Close() error { return nil }

func (c *CordumJobsClient) jobSubmitRequest(req mapper.PolicyCheckRequest, hook, payloadHash string) map[string]any {
	labels := map[string]string{
		"cordclaw.hook": hook,
	}
	if action := strings.TrimSpace(req.Tool); action != "" {
		labels["cordclaw.action"] = action
	}
	if session := strings.TrimSpace(req.Session); session != "" {
		labels["cordclaw.session"] = session
	}
	if turnOrigin := strings.TrimSpace(req.TurnOrigin); turnOrigin != "" {
		labels["cordclaw.turn_origin"] = turnOrigin
	}
	if version := strings.TrimSpace(req.OpenClawVersion); version != "" {
		labels["cordclaw.openclaw_version"] = version
	}
	if agent := strings.TrimSpace(req.Agent); agent != "" {
		labels["cordclaw.agent"] = agent
	}

	body := map[string]any{
		"prompt":          promptForRequest(req, hook),
		"topic":           "job.openclaw." + hook,
		"tenant_id":       c.tenantID,
		"org_id":          c.tenantID,
		"principal_id":    strings.TrimSpace(req.Agent),
		"actor_id":        strings.TrimSpace(req.Agent),
		"actor_type":      "service",
		"idempotency_key": payloadHash,
		"pack_id":         "cordclaw",
		"capability":      strings.TrimSpace(req.Capability),
		"risk_tags":       append([]string(nil), req.RiskTags...),
		"labels":          labels,
		"context":         envelopeForRequest(req, hook),
	}
	return body
}

func promptForRequest(req mapper.PolicyCheckRequest, hook string) string {
	action := strings.TrimSpace(req.Tool)
	if action == "" {
		action = "unknown"
	}
	return fmt.Sprintf("OpenClaw %s action %s", hook, action)
}

func envelopeForRequest(req mapper.PolicyCheckRequest, hook string) map[string]any {
	if len(req.Envelope) > 0 {
		out := make(map[string]any, len(req.Envelope))
		for k, v := range req.Envelope {
			out[k] = v
		}
		return out
	}
	out := map[string]any{
		"hook": hook,
		"tool": strings.TrimSpace(req.Tool),
	}
	if v := strings.TrimSpace(req.Command); v != "" {
		out["command"] = v
	}
	if v := strings.TrimSpace(req.Path); v != "" {
		out["path"] = v
	}
	if v := strings.TrimSpace(req.URL); v != "" {
		out["url"] = v
	}
	if v := strings.TrimSpace(req.Channel); v != "" {
		out["channel"] = v
	}
	if v := strings.TrimSpace(req.Model); v != "" {
		out["model"] = v
	}
	if v := strings.TrimSpace(req.TurnOrigin); v != "" {
		out["turn_origin"] = v
	}
	if v := strings.TrimSpace(req.CronJobID); v != "" {
		out["cron_job_id"] = v
	}
	if v := strings.TrimSpace(req.ParentSession); v != "" {
		out["parent_session"] = v
	}
	if v := strings.TrimSpace(req.OpenClawVersion); v != "" {
		out["openclaw_version"] = v
	}
	return out
}

func decisionFromJobsResponse(raw []byte) (cache.Decision, bool, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return cache.Decision{}, false, nil
	}
	var resp struct {
		JobID          string         `json:"job_id"`
		Status         any            `json:"status"`
		SafetyDecision string         `json:"safety_decision"`
		SafetyReason   string         `json:"safety_reason"`
		SafetyRuleID   string         `json:"safety_rule_id"`
		SafetySnapshot string         `json:"safety_snapshot"`
		Constraints    map[string]any `json:"constraints"`
		ApprovalRef    string         `json:"approval_ref"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return cache.Decision{}, false, err
	}
	decision := strings.ToUpper(strings.TrimSpace(resp.SafetyDecision))
	if decision == "" {
		return cache.Decision{}, false, nil
	}
	out := cache.Decision{
		Decision:    decision,
		Reason:      resp.SafetyReason,
		Constraints: resp.Constraints,
		ApprovalRef: resp.ApprovalRef,
		Snapshot:    resp.SafetySnapshot,
	}
	if out.Decision == "REQUIRE_HUMAN" && out.ApprovalRef == "" {
		out.ApprovalRef = resp.JobID
	}
	return out, true, nil
}

func payloadHash(req mapper.PolicyCheckRequest, tenantID string) (string, error) {
	body, err := MarshalDeterministicPolicyCheckRequest(req, tenantID)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeHook(req mapper.PolicyCheckRequest) string {
	if hook := strings.TrimSpace(req.HookName); hook != "" {
		return hook
	}
	if hook := strings.TrimSpace(req.HookType); hook != "" {
		return hook
	}
	return "before_tool_execution"
}
