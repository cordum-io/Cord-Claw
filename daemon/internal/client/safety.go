package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	capv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type Health struct {
	Connected bool   `json:"connected"`
	State     string `json:"state"`
}

type SafetyClient interface {
	Check(ctx context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error)
	Health(ctx context.Context) Health
	Close() error
}

type GRPCSafetyClient struct {
	conn     *grpc.ClientConn
	client   capv1.SafetyKernelClient
	tenantID string
	apiKey   string
}

func NewGRPCSafetyClient(cfg config.Config) (SafetyClient, error) {
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dialOptions := make([]grpc.DialOption, 0, 2)
	if cfg.KernelInsecure {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{}
		if cfg.KernelTLSCA != "" {
			creds, err := credentials.NewClientTLSFromFile(cfg.KernelTLSCA, "")
			if err != nil {
				return nil, fmt.Errorf("build tls creds: %w", err)
			}
			dialOptions = append(dialOptions, grpc.WithTransportCredentials(creds))
		} else {
			dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		}
	}

	conn, err := grpc.DialContext(dialCtx, cfg.KernelAddr, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("dial safety kernel: %w", err)
	}

	return &GRPCSafetyClient{
		conn:     conn,
		client:   capv1.NewSafetyKernelClient(conn),
		tenantID: normalizeTenant(cfg.TenantID),
		apiKey:   strings.TrimSpace(cfg.APIKey),
	}, nil
}

func NewOfflineSafetyClient() SafetyClient {
	return &offlineSafetyClient{}
}

func (c *GRPCSafetyClient) Check(ctx context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error) {
	if c.conn == nil || c.client == nil {
		return cache.Decision{}, errors.New("safety kernel connection not initialized")
	}

	state := c.conn.GetState()
	if state == connectivity.TransientFailure || state == connectivity.Shutdown {
		return cache.Decision{}, fmt.Errorf("safety kernel unavailable: %s", state.String())
	}

	policyReq := BuildPolicyCheckRequest(req, c.tenantID)
	callCtx := ctx
	if c.apiKey != "" {
		callCtx = metadata.AppendToOutgoingContext(
			callCtx,
			"x-api-key", c.apiKey,
			"authorization", "Bearer "+c.apiKey,
		)
	}

	resp, err := c.client.Check(callCtx, policyReq)
	if err != nil {
		return cache.Decision{}, fmt.Errorf("safety kernel check: %w", err)
	}

	return decisionFromPolicyResponse(resp), nil
}

func (c *GRPCSafetyClient) Health(ctx context.Context) Health {
	if c.conn == nil {
		return Health{Connected: false, State: connectivity.Shutdown.String()}
	}

	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	healthClient := grpcHealth.NewHealthClient(c.conn)
	_, err := healthClient.Check(checkCtx, &grpcHealth.HealthCheckRequest{})
	if err != nil {
		return Health{Connected: false, State: c.conn.GetState().String()}
	}

	return Health{Connected: true, State: c.conn.GetState().String()}
}

func (c *GRPCSafetyClient) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

type offlineSafetyClient struct{}

func (o *offlineSafetyClient) Check(context.Context, mapper.PolicyCheckRequest) (cache.Decision, error) {
	return cache.Decision{}, errors.New("safety kernel offline")
}

func (o *offlineSafetyClient) Health(context.Context) Health {
	return Health{Connected: false, State: "offline"}
}

func (o *offlineSafetyClient) Close() error { return nil }

func BuildPolicyCheckRequest(req mapper.PolicyCheckRequest, tenantID string) *capv1.PolicyCheckRequest {
	tenant := normalizeTenant(tenantID)
	labels := map[string]string{
		"tool": req.Tool,
	}

	if v := strings.TrimSpace(req.Command); v != "" {
		labels["command"] = v
	}
	if v := strings.TrimSpace(req.Path); v != "" {
		labels["path"] = v
	}
	if v := strings.TrimSpace(req.URL); v != "" {
		labels["url"] = v
	}
	if v := strings.TrimSpace(req.Channel); v != "" {
		labels["channel"] = v
	}
	if v := strings.TrimSpace(req.Model); v != "" {
		labels["model"] = v
	}
	if v := strings.TrimSpace(req.HookType); v != "" {
		labels["hookType"] = v
	}
	if v := strings.TrimSpace(req.TurnOrigin); v != "" {
		labels["turnOrigin"] = v
	}
	if v := strings.TrimSpace(req.CronJobID); v != "" {
		labels["cronJobId"] = v
	}
	if v := strings.TrimSpace(req.ParentSession); v != "" {
		labels["parentSession"] = v
	}

	return &capv1.PolicyCheckRequest{
		JobId:       strings.TrimSpace(req.Session),
		Topic:       strings.TrimSpace(req.Topic),
		Tenant:      tenant,
		PrincipalId: strings.TrimSpace(req.Agent),
		Priority:    capv1.JobPriority_JOB_PRIORITY_INTERACTIVE,
		Labels:      labels,
		Meta: &capv1.JobMetadata{
			TenantId:   tenant,
			ActorId:    strings.TrimSpace(req.Agent),
			ActorType:  capv1.ActorType_ACTOR_TYPE_SERVICE,
			Capability: strings.TrimSpace(req.Capability),
			RiskTags:   append([]string(nil), req.RiskTags...),
			Labels:     cloneStringMap(labels),
		},
	}
}

func MarshalDeterministicPolicyCheckRequest(req mapper.PolicyCheckRequest, tenantID string) ([]byte, error) {
	policyReq := BuildPolicyCheckRequest(req, tenantID)
	clone, ok := proto.Clone(policyReq).(*capv1.PolicyCheckRequest)
	if !ok || clone == nil {
		return nil, fmt.Errorf("clone policy request")
	}

	// Job/session id is ephemeral and should not affect cache identity.
	clone.JobId = ""
	return proto.MarshalOptions{Deterministic: true}.Marshal(clone)
}

func decisionFromPolicyResponse(resp *capv1.PolicyCheckResponse) cache.Decision {
	if resp == nil {
		return cache.Decision{
			Decision: "DENY",
			Reason:   "Safety kernel returned empty response",
			Snapshot: "",
		}
	}

	decision := cache.Decision{
		Decision:    mapDecision(resp.GetDecision()),
		Reason:      resp.GetReason(),
		Constraints: constraintsFromProto(resp.GetConstraints()),
		ApprovalRef: resp.GetApprovalRef(),
		Snapshot:    resp.GetPolicySnapshot(),
	}

	if decision.Decision == "REQUIRE_HUMAN" && decision.ApprovalRef == "" && resp.GetApprovalRequired() {
		decision.ApprovalRef = "approval-required"
	}

	return decision
}

func mapDecision(dec capv1.DecisionType) string {
	switch dec {
	case capv1.DecisionType_DECISION_TYPE_ALLOW:
		return "ALLOW"
	case capv1.DecisionType_DECISION_TYPE_DENY:
		return "DENY"
	case capv1.DecisionType_DECISION_TYPE_REQUIRE_HUMAN:
		return "REQUIRE_HUMAN"
	case capv1.DecisionType_DECISION_TYPE_THROTTLE:
		return "THROTTLE"
	case capv1.DecisionType_DECISION_TYPE_ALLOW_WITH_CONSTRAINTS:
		return "CONSTRAIN"
	default:
		return "DENY"
	}
}

func constraintsFromProto(c *capv1.PolicyConstraints) map[string]any {
	if c == nil {
		return nil
	}

	out := map[string]any{}
	if budgets := c.GetBudgets(); budgets != nil {
		if ms := budgets.GetMaxRuntimeMs(); ms > 0 {
			out["timeout"] = (ms + 999) / 1000
		}
	}

	if sandbox := c.GetSandbox(); sandbox != nil {
		out["sandbox"] = sandbox.GetIsolated() ||
			len(sandbox.GetFsReadOnly()) > 0 ||
			len(sandbox.GetFsReadWrite()) > 0 ||
			len(sandbox.GetNetworkAllowlist()) > 0

		if readOnly := sandbox.GetFsReadOnly(); len(readOnly) > 0 {
			out["allowedReadPaths"] = append([]string(nil), readOnly...)
		}
		if readWrite := sandbox.GetFsReadWrite(); len(readWrite) > 0 {
			out["allowedWritePaths"] = append([]string(nil), readWrite...)
		} else if len(sandbox.GetFsReadOnly()) > 0 {
			out["readOnly"] = true
		}
	}

	if diff := c.GetDiff(); diff != nil {
		if maxFiles := diff.GetMaxFiles(); maxFiles > 0 {
			out["maxFiles"] = maxFiles
		}
		if maxLines := diff.GetMaxLines(); maxLines > 0 {
			out["maxLines"] = maxLines
		}
		if denyGlobs := diff.GetDenyPathGlobs(); len(denyGlobs) > 0 {
			out["deniedPaths"] = append([]string(nil), denyGlobs...)
		}
	}

	if redactionLevel := strings.TrimSpace(c.GetRedactionLevel()); redactionLevel != "" {
		out["redactionLevel"] = redactionLevel
	}

	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeTenant(raw string) string {
	tenant := strings.TrimSpace(raw)
	if tenant == "" {
		return "default"
	}
	return tenant
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
