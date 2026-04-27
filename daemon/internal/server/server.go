package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/circuit"
	"github.com/cordum-io/cordclaw/daemon/internal/client"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
	"github.com/cordum-io/cordclaw/daemon/internal/policy"
	"github.com/cordum-io/cordclaw/daemon/internal/ratelimit"
	"github.com/cordum-io/cordclaw/daemon/internal/redact"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CheckRequest struct {
	Tool                 string            `json:"tool"`
	Hook                 string            `json:"hook,omitempty"`
	HookType             string            `json:"hookType,omitempty"`
	Command              string            `json:"command,omitempty"`
	Path                 string            `json:"path,omitempty"`
	URL                  string            `json:"url,omitempty"`
	Channel              string            `json:"channel,omitempty"`
	Agent                string            `json:"agent,omitempty"`
	AgentID              string            `json:"agent_id,omitempty"`
	Session              string            `json:"session,omitempty"`
	Model                string            `json:"model,omitempty"`
	Provider             string            `json:"provider,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
	PromptText           string            `json:"prompt_text,omitempty"`
	TurnOrigin           string            `json:"turnOrigin,omitempty"`
	TurnOriginSnake      string            `json:"turn_origin,omitempty"`
	CronJobID            string            `json:"cronJobId,omitempty"`
	CronJobIDSnake       string            `json:"cron_job_id,omitempty"`
	ParentSession        string            `json:"parentSession,omitempty"`
	ParentSessionID      string            `json:"parent_session_id,omitempty"`
	OpenClawVersion      string            `json:"openclawVersion,omitempty"`
	OpenClawVersionSnake string            `json:"openclaw_version,omitempty"`
	Envelope             map[string]any    `json:"envelope,omitempty"`
}

func (r CheckRequest) normalizedHookType() string {
	if hookType := strings.TrimSpace(r.HookType); hookType != "" {
		return hookType
	}
	return strings.TrimSpace(r.Hook)
}

func (r CheckRequest) normalizedAgent() string {
	if agent := strings.TrimSpace(r.Agent); agent != "" {
		return agent
	}
	return strings.TrimSpace(r.AgentID)
}

func (r CheckRequest) normalizedTurnOrigin() string {
	if origin := strings.TrimSpace(r.TurnOrigin); origin != "" {
		return origin
	}
	return strings.TrimSpace(r.TurnOriginSnake)
}

func (r CheckRequest) normalizedCronJobID() string {
	if jobID := strings.TrimSpace(r.CronJobID); jobID != "" {
		return jobID
	}
	return strings.TrimSpace(r.CronJobIDSnake)
}

func (r CheckRequest) normalizedParentSession() string {
	if session := strings.TrimSpace(r.ParentSession); session != "" {
		return session
	}
	return strings.TrimSpace(r.ParentSessionID)
}

func (r CheckRequest) normalizedOpenClawVersion() string {
	if version := strings.TrimSpace(r.OpenClawVersion); version != "" {
		return version
	}
	return strings.TrimSpace(r.OpenClawVersionSnake)
}

func (r CheckRequest) normalizedLabels() map[string]string {
	labels := cloneStringMap(r.Labels)
	mergeStringAnyLabels(labels, r.Envelope["labels"])
	mergeStringAnyLabels(labels, r.Envelope["policy_labels"])
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	return out
}

func mergeStringAnyLabels(dst map[string]string, raw any) {
	switch labels := raw.(type) {
	case map[string]string:
		for k, v := range labels {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			dst[key] = strings.TrimSpace(v)
		}
	case map[string]any:
		for k, v := range labels {
			key := strings.TrimSpace(k)
			if key == "" {
				continue
			}
			dst[key] = strings.TrimSpace(fmt.Sprint(v))
		}
	}
}

type PolicyResponse struct {
	Decision         string         `json:"decision"`
	Reason           string         `json:"reason"`
	Constraints      map[string]any `json:"constraints,omitempty"`
	ApprovalRef      string         `json:"approvalRef,omitempty"`
	GovernanceStatus string         `json:"governanceStatus"`
	Cached           bool           `json:"cached"`
	LatencyMs        float64        `json:"latencyMs"`
}

type StatusResponse struct {
	Daemon           string `json:"daemon"`
	Kernel           string `json:"kernel"`
	Snapshot         string `json:"snapshot"`
	GovernanceStatus string `json:"governanceStatus"`
	CacheSize        int    `json:"cacheSize"`
	Breaker          string `json:"breaker"`
}

type AuditEntry struct {
	Timestamp string         `json:"timestamp"`
	Tool      string         `json:"tool,omitempty"`
	Decision  string         `json:"decision,omitempty"`
	Reason    string         `json:"reason,omitempty"`
	Cached    bool           `json:"cached,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
}

type summaryJobSubmitter interface {
	Submit(ctx context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error)
}

type Handler struct {
	cfg       config.Config
	gating    client.SafetyClient
	cache     *cache.LRU
	breaker   *circuit.Breaker
	auditMu   sync.Mutex
	auditLog  []AuditEntry
	auditSize int

	policyRateLimitMu    sync.RWMutex
	policyRateLimitCache map[string]float64

	snapshotMu sync.RWMutex
	snapshot   string

	promptScanner *redact.Scanner
	promptDLP     redact.Policy
	dlpMetrics    *dlpMetrics
	cronLog       *policy.CronDecisionLog
	emitter       *ratelimit.Emitter
	promReg       *prometheus.Registry

	shadowRules       []policy.Rule
	onShadowEvent     func(policy.ShadowEvent)
	shadowMetric      prometheus.Counter
	shadowCallbackSem chan struct{}

	gcStop chan struct{}
	gcDone chan struct{}
}

func New(cfg config.Config, gating client.SafetyClient) *Handler {
	return newWithCallbacks(cfg, gating, nil, nil)
}

func newWithRateLimitSummary(cfg config.Config, gating client.SafetyClient, onSummary func(string, int)) *Handler {
	return newWithCallbacks(cfg, gating, onSummary, nil)
}

func newWithShadowEventCallback(cfg config.Config, gating client.SafetyClient, onShadowEvent func(policy.ShadowEvent)) *Handler {
	return newWithCallbacks(cfg, gating, nil, onShadowEvent)
}

func newWithCallbacks(cfg config.Config, gating client.SafetyClient, onSummary func(string, int), onShadowEvent func(policy.ShadowEvent)) *Handler {
	decisionCache := cache.New(cfg.CacheMaxSize)
	if gating == nil {
		var err error
		if strings.TrimSpace(cfg.CordumGatewayURL) != "" {
			gating, err = client.NewCordumJobsClient(cfg, decisionCache)
			if err != nil {
				log.Printf("[cordclaw-daemon] cordum jobs client initialization degraded: %v", err)
			}
		} else {
			log.Printf("[cordclaw-daemon] falling back to gRPC Safety Kernel; deprecated path; set CORDCLAW_CORDUM_GATEWAY_URL to migrate to /api/v1/jobs")
			gating, err = client.NewGRPCSafetyClient(cfg)
			if err != nil {
				log.Printf("[cordclaw-daemon] safety client initialization degraded: %v", err)
			}
		}
		if gating == nil {
			gating = client.NewOfflineSafetyClient()
		}
	}

	promptPolicy := redact.DefaultPolicy()
	if strings.TrimSpace(cfg.DLPPolicyPath) != "" {
		loaded, err := redact.LoadPolicyFile(cfg.DLPPolicyPath)
		if err != nil {
			log.Printf("[cordclaw-daemon] prompt dlp policy load failed; using defaults: %v", err)
		} else {
			promptPolicy = loaded
		}
	}
	promptScanner, err := redact.NewScanner(promptPolicy.Patterns, promptPolicy.Action)
	if err != nil {
		log.Printf("[cordclaw-daemon] prompt dlp initialization failed: %v", err)
	}
	shadowPolicyPath := strings.TrimSpace(cfg.ShadowPolicyPath)
	if shadowPolicyPath == "" {
		shadowPolicyPath = strings.TrimSpace(cfg.DLPPolicyPath)
	}
	shadowRules, err := policy.LoadRulesFile(shadowPolicyPath)
	if err != nil {
		log.Printf("[cordclaw-daemon] shadow policy load failed; shadow rules disabled: %v", err)
	}
	promReg := prometheus.NewRegistry()
	shadowMetric := newShadowEventsCounter(promReg)
	if onShadowEvent == nil {
		onShadowEvent = defaultShadowEventCallback
	}
	if onSummary == nil {
		if submitter, ok := gating.(summaryJobSubmitter); ok {
			onSummary = rateLimitSummaryJobCallback(submitter)
		}
	}
	emitter := ratelimit.New(effectiveEmitRateLimit(cfg.EmitRateLimit), onSummary, promReg)
	h := &Handler{
		cfg:                  cfg,
		gating:               gating,
		cache:                decisionCache,
		breaker:              circuit.New(circuit.DefaultConfig()),
		auditLog:             make([]AuditEntry, 0, 256),
		auditSize:            1000,
		policyRateLimitCache: make(map[string]float64),
		snapshot:             "bootstrap",
		promptScanner:        promptScanner,
		promptDLP:            promptPolicy,
		dlpMetrics:           newDLPMetrics(),
		cronLog:              policy.NewCronDecisionLog(24 * time.Hour),
		emitter:              emitter,
		promReg:              promReg,
		shadowRules:          shadowRules,
		onShadowEvent:        onShadowEvent,
		shadowMetric:         shadowMetric,
		shadowCallbackSem:    make(chan struct{}, shadowCallbackConcurrency()),
		gcStop:               make(chan struct{}),
		gcDone:               make(chan struct{}),
	}
	h.startRateLimitGC()
	return h
}

func effectiveEmitRateLimit(value float64) float64 {
	if value < 1 {
		return 50
	}
	return value
}

func (h *Handler) emitRateLimitFor(req mapper.PolicyCheckRequest) float64 {
	if limit, ok := h.lookupPolicyRateLimit(req.Agent); ok {
		return limit
	}
	return effectiveEmitRateLimit(h.cfg.EmitRateLimit)
}

const (
	policyEmitRateLimitConstraintKey = "cordclaw.emit_rate_limit_rps"
	minPolicyEmitRateLimit           = 1.0
	maxPolicyEmitRateLimit           = 1000.0
)

func (h *Handler) lookupPolicyRateLimit(agent string) (float64, bool) {
	agent = normalizePolicyRateLimitAgent(agent)
	h.policyRateLimitMu.RLock()
	defer h.policyRateLimitMu.RUnlock()
	limit, ok := h.policyRateLimitCache[agent]
	return limit, ok
}

func (h *Handler) recordPolicyRateLimit(agent string, decision cache.Decision) {
	raw, ok := decision.Constraints[policyEmitRateLimitConstraintKey]
	if !ok {
		return
	}
	limit, ok := parsePolicyRateLimit(raw)
	if !ok {
		return
	}
	agent = normalizePolicyRateLimitAgent(agent)
	h.policyRateLimitMu.Lock()
	defer h.policyRateLimitMu.Unlock()
	h.policyRateLimitCache[agent] = limit
}

func (h *Handler) clearPolicyRateLimitCache() {
	h.policyRateLimitMu.Lock()
	defer h.policyRateLimitMu.Unlock()
	h.policyRateLimitCache = make(map[string]float64)
}

func normalizePolicyRateLimitAgent(agent string) string {
	agent = strings.TrimSpace(agent)
	if agent == "" {
		return "unknown"
	}
	return agent
}

func parsePolicyRateLimit(raw any) (float64, bool) {
	var limit float64
	switch value := raw.(type) {
	case float64:
		limit = value
	case int:
		limit = float64(value)
	case json.Number:
		parsed, err := value.Float64()
		if err != nil {
			return 0, false
		}
		limit = parsed
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		if err != nil {
			return 0, false
		}
		limit = parsed
	default:
		return 0, false
	}
	if math.IsNaN(limit) || math.IsInf(limit, 0) || limit < minPolicyEmitRateLimit || limit > maxPolicyEmitRateLimit {
		return 0, false
	}
	return limit, true
}

func rateLimitSummaryJobCallback(submitter summaryJobSubmitter) func(string, int) {
	return func(agentID string, count int) {
		if count <= 0 || submitter == nil {
			return
		}
		agentID = strings.TrimSpace(agentID)
		if agentID == "" {
			agentID = "unknown"
		}
		windowStart := time.Now().UTC().Truncate(time.Second).Unix()
		labels := map[string]string{
			"cordclaw.rate_limited": "true",
			"agent_id":              agentID,
			"denied_count":          strconv.Itoa(count),
			"window_start":          strconv.FormatInt(windowStart, 10),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, err := submitter.Submit(ctx, mapper.PolicyCheckRequest{
			Topic:      "job.openclaw.rate_limit_summary",
			Capability: "openclaw.rate-limit-summary",
			Tool:       "rate_limit_summary",
			HookName:   "rate_limit_summary",
			HookType:   "rate_limit_summary",
			Agent:      agentID,
			RiskTags:   []string{"rate_limited"},
			Labels:     labels,
			Envelope: map[string]any{
				"agent_id":              agentID,
				"denied_count":          count,
				"window_start":          windowStart,
				"cordclaw.rate_limited": true,
			},
		})
		if err != nil {
			log.Printf("[cordclaw-daemon] rate-limit summary job emission failed agent_id=%s count=%d: %v", agentID, count, err)
		}
	}
}

func (h *Handler) startRateLimitGC() {
	if h == nil || h.emitter == nil || h.gcStop == nil || h.gcDone == nil {
		return
	}
	go func() {
		defer close(h.gcDone)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				h.emitter.GC()
			case <-h.gcStop:
				return
			}
		}
	}()
}

func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	if h.gcStop != nil {
		select {
		case <-h.gcStop:
		default:
			close(h.gcStop)
		}
	}
	if h.gcDone != nil {
		<-h.gcDone
	}
	if h.emitter != nil {
		h.emitter.Close()
	}
	if h.gating == nil {
		return nil
	}
	return h.gating.Close()
}

func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", h.handleCheck)
	mux.HandleFunc("/simulate", h.handleSimulate)
	mux.HandleFunc("/audit", h.handleAudit)
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/status", h.handleStatus)
	if h.promReg != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(h.promReg, promhttp.HandlerOpts{}))
	}
	return mux
}

func (h *Handler) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	start := time.Now()

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	hookType := req.normalizedHookType()
	if hookType == "before_prompt_build" {
		h.handlePromptBuildCheck(w, req, start)
		return
	}

	mapped, err := mapper.Map(mapper.OpenClawAction{
		Tool:            strings.TrimSpace(req.Tool),
		HookType:        hookType,
		Command:         req.Command,
		Path:            req.Path,
		URL:             req.URL,
		Channel:         req.Channel,
		Agent:           req.normalizedAgent(),
		Session:         req.Session,
		Model:           req.Model,
		Labels:          req.normalizedLabels(),
		TurnOrigin:      req.normalizedTurnOrigin(),
		CronJobID:       req.normalizedCronJobID(),
		ParentSession:   req.normalizedParentSession(),
		OpenClawVersion: req.normalizedOpenClawVersion(),
		Envelope:        req.Envelope,
	})
	if err != nil {
		if hookType == "before_agent_start" {
			response := h.deniedResponse(start, err.Error())
			h.appendAudit(AuditEntry{
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Tool:      "agent_start",
				Decision:  response.Decision,
				Reason:    response.Reason,
				Details: map[string]any{
					"hook":        hookType,
					"turn_origin": req.normalizedTurnOrigin(),
				},
			})
			if h.cfg.LogDecisions {
				log.Printf("[cordclaw-daemon] action=agent_start decision=DENY reason=%s", response.Reason)
			}
			writeJSON(w, http.StatusOK, response)
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	var response PolicyResponse
	var denied bool
	mapped, response, denied = h.applyCronOriginCheck(mapped, start)
	if denied {
		h.appendAudit(AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Tool:      mapped.Tool,
			Decision:  response.Decision,
			Reason:    response.Reason,
			Details: map[string]any{
				"hook":         mapped.HookType,
				"turn_origin":  mapped.TurnOrigin,
				"cron_job_id":  mapped.CronJobID,
				"risk_tags":    append([]string(nil), mapped.RiskTags...),
				"origin_check": "cron_origin_check",
			},
		})
		if h.cfg.LogDecisions {
			log.Printf("[cordclaw-daemon] action=agent_start decision=DENY reason=%s", response.Reason)
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	if h.emitter != nil && !h.emitter.AllowWithLimit(mapped.Agent, h.emitRateLimitFor(mapped)) {
		response := h.deniedResponse(start, "rate_limited")
		h.appendAudit(AuditEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Tool:      mapped.Tool,
			Decision:  response.Decision,
			Reason:    response.Reason,
			Details: map[string]any{
				"hook":       mapped.HookType,
				"agent_id":   mapped.Agent,
				"risk_tags":  append([]string(nil), mapped.RiskTags...),
				"rate_limit": true,
			},
		})
		if h.cfg.LogDecisions {
			log.Printf("[cordclaw-daemon] action=%s decision=DENY reason=rate_limited", mapped.Tool)
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	snapshot := h.getSnapshot()
	cacheKey := makeCacheKey(snapshot, h.cfg.TenantID, mapped)
	if cachedDecision, ok := h.cache.Get(cacheKey); ok {
		response := h.toResponse(cachedDecision, true, start)
		h.appendAudit(AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Tool: req.Tool, Decision: response.Decision, Reason: response.Reason, Cached: true})
		h.recordCronCreateAllow(mapped, response)
		writeJSON(w, http.StatusOK, response)
		return
	}

	now := time.Now()
	if !h.breaker.Allow(now) {
		response := h.degradedResponse(start)
		h.appendAudit(AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Tool: req.Tool, Decision: response.Decision, Reason: response.Reason})
		writeJSON(w, http.StatusOK, response)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	decision, err := h.gating.Check(ctx, mapped)
	if err != nil {
		h.breaker.OnFailure(now)
		if h.cfg.LogDecisions {
			log.Printf("[cordclaw-daemon] policy check error: %v", err)
		}
		response := h.degradedResponse(start)
		h.appendAudit(AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Tool: req.Tool, Decision: response.Decision, Reason: response.Reason})
		writeJSON(w, http.StatusOK, response)
		return
	}

	h.breaker.OnSuccess(now)
	h.updateSnapshot(decision.Snapshot)
	h.recordPolicyRateLimit(mapped.Agent, decision)
	cacheKey = makeCacheKey(h.getSnapshot(), h.cfg.TenantID, mapped)
	h.cache.Set(cacheKey, decision, h.cfg.CacheTTL)
	h.evaluateShadowRules(mapped)

	response = h.toResponse(decision, false, start)
	h.appendAudit(AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Tool: req.Tool, Decision: response.Decision, Reason: response.Reason, Cached: false})
	h.recordCronCreateAllow(mapped, response)
	writeJSON(w, http.StatusOK, response)
}

func (h *Handler) evaluateShadowRules(mapped mapper.PolicyCheckRequest) {
	if h == nil || len(h.shadowRules) == 0 {
		return
	}
	_, events := policy.EvaluateWithShadow(h.shadowRules, policy.Envelope{
		Topic:    mapped.Topic,
		Tool:     mapped.Tool,
		HookName: mapped.HookName,
		RiskTags: append([]string(nil), mapped.RiskTags...),
		Labels:   cloneStringMap(mapped.Labels),
	})
	for _, ev := range events {
		h.dispatchShadowEvent(ev)
	}
}

func (h *Handler) dispatchShadowEvent(ev policy.ShadowEvent) {
	if h == nil {
		return
	}
	if h.shadowMetric != nil {
		h.shadowMetric.Inc()
	}
	if h.onShadowEvent == nil {
		return
	}
	if h.shadowCallbackSem == nil {
		h.safeShadowCallback(ev)
		return
	}
	select {
	case h.shadowCallbackSem <- struct{}{}:
		go func() {
			defer func() { <-h.shadowCallbackSem }()
			h.safeShadowCallback(ev)
		}()
	default:
		log.Printf("[cordclaw-daemon] shadow event callback backlog full; dropping callback rule_id=%s hook=%s", ev.RuleID, ev.HookName)
	}
}

func (h *Handler) safeShadowCallback(ev policy.ShadowEvent) {
	defer func() {
		if recovered := recover(); recovered != nil {
			slog.Warn("cordclaw shadow callback panicked", "rule_id", ev.RuleID, "hook", ev.HookName)
		}
	}()
	h.onShadowEvent(ev)
}

func defaultShadowEventCallback(ev policy.ShadowEvent) {
	// TODO(task-fc766e2a): wire onShadowEvent to s.cordumJobs.SubmitJob on topic
	// job.openclaw.<hook> with labels {cordclaw.shadow=true,
	// cordclaw.would_decision=<X>, cordclaw.would_reason=<str>,
	// cordclaw.rule_id=<id>} once the shadow-emission follow-up lands.
	slog.Info("cordclaw shadow event", "rule_id", ev.RuleID, "would_decision", ev.WouldDecision, "would_reason", ev.WouldReason, "hook", ev.HookName)
}

func shadowCallbackConcurrency() int {
	limit := runtime.GOMAXPROCS(0) * 4
	if limit < 1 {
		return 1
	}
	return limit
}

func (h *Handler) handlePromptBuildCheck(w http.ResponseWriter, req CheckRequest, start time.Time) {
	snapshot := h.getSnapshot()
	cacheKey := makePromptBuildCacheKey(snapshot, h.cfg.TenantID, req.Hook, h.promptDLP.Action, req.PromptText)
	if cachedDecision, ok := h.cache.Get(cacheKey); ok {
		response := h.toResponse(cachedDecision, true, start)
		h.appendPromptDLPAudit(req, response, nil, true)
		if h.dlpMetrics != nil {
			h.dlpMetrics.recordDecision(response.Decision)
		}
		writeJSON(w, http.StatusOK, response)
		return
	}

	decision := cache.Decision{
		Decision: "DENY",
		Reason:   "prompt_dlp_unavailable",
		Snapshot: snapshot,
	}
	var matches []redact.Match
	if h.promptScanner != nil {
		redactDecision, found := h.promptScanner.Scan(req.PromptText)
		matches = found
		decision = promptDLPDecisionToCacheDecision(redactDecision, snapshot, len(found))
	}

	h.cache.Set(cacheKey, decision, h.cfg.CacheTTL)
	response := h.toResponse(decision, false, start)
	h.appendPromptDLPAudit(req, response, matches, false)
	if h.dlpMetrics != nil {
		h.dlpMetrics.recordDecision(response.Decision)
		h.dlpMetrics.recordMatches(matches)
	}
	if h.cfg.LogDecisions {
		log.Printf("[cordclaw-daemon] prompt dlp decision hook=%s action=%s match_count=%d", req.Hook, response.Decision, len(matches))
	}
	writeJSON(w, http.StatusOK, response)
}

func promptDLPDecisionToCacheDecision(decision redact.Decision, snapshot string, matchCount int) cache.Decision {
	out := cache.Decision{
		Decision: decision.Action,
		Reason:   decision.Reason,
		Snapshot: snapshot,
	}
	switch decision.Action {
	case redact.ActionAllow:
		if out.Reason == "" {
			out.Reason = "prompt accepted"
		}
	case redact.ActionConstrain:
		if out.Reason == "" {
			out.Reason = "prompt redacted"
		}
		out.Constraints = map[string]any{
			"kind":            "prompt_redact",
			"modified_prompt": decision.ModifiedPrompt,
			"match_count":     matchCount,
		}
	case redact.ActionDeny:
		if out.Reason == "" {
			out.Reason = "prompt blocked"
		}
	default:
		out.Decision = "DENY"
		out.Reason = "prompt_dlp_unknown_decision"
	}
	return out
}

func (h *Handler) appendPromptDLPAudit(req CheckRequest, response PolicyResponse, matches []redact.Match, cached bool) {
	details := map[string]any{
		"hook":        req.Hook,
		"match_count": len(matches),
	}
	if req.Agent != "" {
		details["agent"] = req.Agent
	}
	if req.AgentID != "" {
		details["agent_id"] = req.AgentID
	}
	if req.Provider != "" {
		details["provider"] = req.Provider
	}
	if req.Model != "" {
		details["model"] = req.Model
	}
	if len(matches) > 0 {
		details["patterns"] = promptDLPMatchNames(matches)
	}
	h.appendAudit(AuditEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Tool:      req.Tool,
		Decision:  response.Decision,
		Reason:    response.Reason,
		Cached:    cached,
		Details:   details,
	})
}

func promptDLPMatchNames(matches []redact.Match) []string {
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		if _, ok := seen[match.Name]; ok {
			continue
		}
		seen[match.Name] = struct{}{}
		names = append(names, match.Name)
	}
	return names
}

func (h *Handler) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	start := time.Now()
	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	mapped, err := mapper.Map(mapper.OpenClawAction{
		Tool:            strings.TrimSpace(req.Tool),
		HookType:        req.normalizedHookType(),
		Command:         req.Command,
		Path:            req.Path,
		URL:             req.URL,
		Channel:         req.Channel,
		Agent:           req.normalizedAgent(),
		Session:         req.Session,
		Model:           req.Model,
		Labels:          req.normalizedLabels(),
		TurnOrigin:      req.normalizedTurnOrigin(),
		CronJobID:       req.normalizedCronJobID(),
		ParentSession:   req.normalizedParentSession(),
		OpenClawVersion: req.normalizedOpenClawVersion(),
		Envelope:        req.Envelope,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	decision, err := h.gating.Check(ctx, mapped)
	if err != nil {
		writeJSON(w, http.StatusOK, h.degradedResponse(start))
		return
	}

	writeJSON(w, http.StatusOK, h.toResponse(decision, false, start))
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		entries := h.listAudit(limit)
		writeJSON(w, http.StatusOK, map[string]any{"decisions": entries})
	case http.MethodPost:
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
			return
		}
		entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Details: payload}
		if tool, ok := payload["tool"].(string); ok {
			entry.Tool = tool
		}
		h.appendAudit(entry)
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "recorded"})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	health := h.gating.Health(r.Context())
	status := "degraded"
	kernel := "unreachable"
	if health.Connected {
		status = "connected"
		kernel = "connected"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"daemon":           "ok",
		"kernel":           kernel,
		"governanceStatus": status,
		"breaker":          h.breaker.State(time.Now()),
	})
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	health := h.gating.Health(r.Context())
	governanceStatus := "degraded"
	kernelStatus := "degraded"
	if health.Connected && h.breaker.State(time.Now()) == circuit.StateClosed {
		governanceStatus = "connected"
		kernelStatus = "connected"
	}
	if !health.Connected && h.cfg.FailMode == "closed" {
		governanceStatus = "offline"
		kernelStatus = "offline"
	}

	resp := StatusResponse{
		Daemon:           "ok",
		Kernel:           kernelStatus,
		Snapshot:         h.getSnapshot(),
		GovernanceStatus: governanceStatus,
		CacheSize:        h.cache.Size(),
		Breaker:          string(h.breaker.State(time.Now())),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) toResponse(decision cache.Decision, cached bool, started time.Time) PolicyResponse {
	status := "connected"
	if h.breaker.State(time.Now()) == circuit.StateOpen {
		status = "degraded"
	}
	if !h.gating.Health(context.Background()).Connected {
		if h.cfg.FailMode == "closed" {
			status = "offline"
		} else if status == "connected" {
			status = "degraded"
		}
	}
	return PolicyResponse{
		Decision:         decision.Decision,
		Reason:           decision.Reason,
		Constraints:      decision.Constraints,
		ApprovalRef:      decision.ApprovalRef,
		GovernanceStatus: status,
		Cached:           cached,
		LatencyMs:        roundLatencyMs(time.Since(started)),
	}
}

func (h *Handler) degradedResponse(started time.Time) PolicyResponse {
	status := "degraded"
	switch h.cfg.FailMode {
	case "open":
		return PolicyResponse{
			Decision:         "ALLOW",
			Reason:           "Safety kernel unreachable; fail mode open",
			GovernanceStatus: status,
			Cached:           false,
			LatencyMs:        roundLatencyMs(time.Since(started)),
		}
	case "closed":
		status = "offline"
		return PolicyResponse{
			Decision:         "DENY",
			Reason:           "Safety kernel unreachable; fail mode closed",
			GovernanceStatus: status,
			Cached:           false,
			LatencyMs:        roundLatencyMs(time.Since(started)),
		}
	default:
		return PolicyResponse{
			Decision:         "DENY",
			Reason:           "Governance degraded and no cached policy decision available",
			GovernanceStatus: status,
			Cached:           false,
			LatencyMs:        roundLatencyMs(time.Since(started)),
		}
	}
}

func (h *Handler) deniedResponse(started time.Time, reason string) PolicyResponse {
	return PolicyResponse{
		Decision:         "DENY",
		Reason:           reason,
		GovernanceStatus: "connected",
		Cached:           false,
		LatencyMs:        roundLatencyMs(time.Since(started)),
	}
}

func (h *Handler) applyCronOriginCheck(mapped mapper.PolicyCheckRequest, started time.Time) (mapper.PolicyCheckRequest, PolicyResponse, bool) {
	if mapped.Topic != "job.openclaw.agent_start" || !hasRiskTag(mapped.RiskTags, "cron_fire") {
		return mapped, PolicyResponse{}, false
	}
	if _, ok := h.cronLog.Lookup(mapped.CronJobID); ok {
		mapped.RiskTags = replaceRiskTag(mapped.RiskTags, "cron_fire", "cron_origin_verified")
		return mapped, PolicyResponse{}, false
	}
	return mapped, h.deniedResponse(started, "cron-origin-policy-mismatch"), true
}

func (h *Handler) recordCronCreateAllow(mapped mapper.PolicyCheckRequest, response PolicyResponse) {
	if mapped.Tool != "cron.create" || response.Decision != "ALLOW" || response.GovernanceStatus != "connected" {
		return
	}
	h.cronLog.Record(mapped.CronJobID, policy.CronDecisionRecord{
		AllowedTopics: []string{mapped.Topic},
		AllowedTags:   append([]string(nil), mapped.RiskTags...),
		Agent:         mapped.Agent,
	})
}

func hasRiskTag(tags []string, target string) bool {
	for _, tag := range tags {
		if tag == target {
			return true
		}
	}
	return false
}

func replaceRiskTag(tags []string, remove string, add string) []string {
	tagSet := make(map[string]struct{}, len(tags)+1)
	for _, tag := range tags {
		if tag == remove {
			continue
		}
		tagSet[tag] = struct{}{}
	}
	if add != "" {
		tagSet[add] = struct{}{}
	}
	out := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func (h *Handler) getSnapshot() string {
	h.snapshotMu.RLock()
	defer h.snapshotMu.RUnlock()
	return h.snapshot
}

func (h *Handler) updateSnapshot(snapshot string) {
	snapshot = strings.TrimSpace(snapshot)
	if snapshot == "" {
		return
	}
	h.snapshotMu.Lock()
	defer h.snapshotMu.Unlock()
	if h.snapshot != snapshot {
		h.snapshot = snapshot
		h.cache.Clear()
		h.clearPolicyRateLimitCache()
	}
}

func (h *Handler) appendAudit(entry AuditEntry) {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	h.auditLog = append(h.auditLog, entry)
	if len(h.auditLog) > h.auditSize {
		h.auditLog = h.auditLog[len(h.auditLog)-h.auditSize:]
	}
}

func (h *Handler) listAudit(limit int) []AuditEntry {
	h.auditMu.Lock()
	defer h.auditMu.Unlock()
	if limit > len(h.auditLog) {
		limit = len(h.auditLog)
	}
	out := make([]AuditEntry, 0, limit)
	for i := len(h.auditLog) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, h.auditLog[i])
	}
	return out
}

func makeCacheKey(snapshot string, tenantID string, req mapper.PolicyCheckRequest) string {
	body, err := client.MarshalDeterministicPolicyCheckRequest(req, tenantID)
	if err != nil {
		hash := sha256.Sum256([]byte(snapshot))
		return fmt.Sprintf("%s:%s:%s", snapshot, tenantID, cache.KeyForHook(req.HookName, req.Tool, hex.EncodeToString(hash[:])))
	}
	hash := sha256.Sum256(body)
	return fmt.Sprintf("%s:%s:%s", snapshot, tenantID, cache.KeyForHook(req.HookName, req.Tool, hex.EncodeToString(hash[:])))
}

func makePromptBuildCacheKey(snapshot string, tenantID string, hook string, action string, promptText string) string {
	promptHash := sha256.Sum256([]byte(promptText))
	parts := []string{
		strings.TrimSpace(hook),
		strings.TrimSpace(action),
		hex.EncodeToString(promptHash[:]),
	}
	return fmt.Sprintf("%s:%s:%s", snapshot, tenantID, strings.Join(parts, "|"))
}

func roundLatencyMs(d time.Duration) float64 {
	ms := float64(d.Microseconds()) / 1000
	return float64(int(ms*100+0.5)) / 100
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
