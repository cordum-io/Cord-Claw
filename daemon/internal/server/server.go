package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
)

type CheckRequest struct {
	Tool    string `json:"tool"`
	Command string `json:"command,omitempty"`
	Path    string `json:"path,omitempty"`
	URL     string `json:"url,omitempty"`
	Channel string `json:"channel,omitempty"`
	Agent   string `json:"agent,omitempty"`
	Session string `json:"session,omitempty"`
	Model   string `json:"model,omitempty"`
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

type Handler struct {
	cfg       config.Config
	safety    client.SafetyClient
	cache     *cache.LRU
	breaker   *circuit.Breaker
	auditMu   sync.Mutex
	auditLog  []AuditEntry
	auditSize int

	snapshotMu sync.RWMutex
	snapshot   string
}

func New(cfg config.Config, safety client.SafetyClient) *Handler {
	return &Handler{
		cfg:       cfg,
		safety:    safety,
		cache:     cache.New(cfg.CacheMaxSize),
		breaker:   circuit.New(circuit.DefaultConfig()),
		auditLog:  make([]AuditEntry, 0, 256),
		auditSize: 1000,
		snapshot:  "bootstrap",
	}
}

func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/check", h.handleCheck)
	mux.HandleFunc("/simulate", h.handleSimulate)
	mux.HandleFunc("/audit", h.handleAudit)
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/status", h.handleStatus)
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

	mapped, err := mapper.Map(mapper.OpenClawAction{
		Tool:    strings.TrimSpace(req.Tool),
		Command: req.Command,
		Path:    req.Path,
		URL:     req.URL,
		Channel: req.Channel,
		Agent:   req.Agent,
		Session: req.Session,
		Model:   req.Model,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	snapshot := h.getSnapshot()
	cacheKey := makeCacheKey(snapshot, mapped)
	if cachedDecision, ok := h.cache.Get(cacheKey); ok {
		response := h.toResponse(cachedDecision, true, start)
		h.appendAudit(AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Tool: req.Tool, Decision: response.Decision, Reason: response.Reason, Cached: true})
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
	decision, err := h.safety.Check(ctx, mapped)
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
	cacheKey = makeCacheKey(h.getSnapshot(), mapped)
	h.cache.Set(cacheKey, decision, h.cfg.CacheTTL)

	response := h.toResponse(decision, false, start)
	h.appendAudit(AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Tool: req.Tool, Decision: response.Decision, Reason: response.Reason, Cached: false})
	writeJSON(w, http.StatusOK, response)
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
		Tool:    strings.TrimSpace(req.Tool),
		Command: req.Command,
		Path:    req.Path,
		URL:     req.URL,
		Channel: req.Channel,
		Agent:   req.Agent,
		Session: req.Session,
		Model:   req.Model,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	decision, err := h.safety.Check(ctx, mapped)
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

	health := h.safety.Health(r.Context())
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

	health := h.safety.Health(r.Context())
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
	if !h.safety.Health(context.Background()).Connected {
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

func makeCacheKey(snapshot string, req mapper.PolicyCheckRequest) string {
	req.Session = ""
	sortedTags := append([]string(nil), req.RiskTags...)
	sort.Strings(sortedTags)
	req.RiskTags = sortedTags

	body, _ := json.Marshal(req)
	hash := sha256.Sum256(body)
	return fmt.Sprintf("%s:%s", snapshot, hex.EncodeToString(hash[:]))
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
