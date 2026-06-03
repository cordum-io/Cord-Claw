package client

import (
	"bytes"
	"context"
	"net"
	"testing"

	capv1 "github.com/cordum-io/cap/v2/cordum/agent/v1"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type testSafetyKernelServer struct {
	capv1.UnimplementedSafetyKernelServer
	resp   *capv1.PolicyCheckResponse
	err    error
	lastMD metadata.MD
	last   *capv1.PolicyCheckRequest
}

func (s *testSafetyKernelServer) Check(ctx context.Context, req *capv1.PolicyCheckRequest) (*capv1.PolicyCheckResponse, error) {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		s.lastMD = md.Copy()
	}
	if req != nil {
		if clone, ok := proto.Clone(req).(*capv1.PolicyCheckRequest); ok {
			s.last = clone
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

func newBufconnClient(t *testing.T, srv *testSafetyKernelServer) (*GRPCSafetyClient, func()) {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	capv1.RegisterSafetyKernelServer(server, srv)
	go func() {
		_ = server.Serve(lis)
	}()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.DialContext(
		context.Background(),
		"passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}

	client := &GRPCSafetyClient{
		conn:     conn,
		client:   capv1.NewSafetyKernelClient(conn),
		tenantID: "tenant-a",
		apiKey:   "api-key-123",
	}

	cleanup := func() {
		server.Stop()
		_ = conn.Close()
		_ = lis.Close()
	}
	return client, cleanup
}

func TestGRPCSafetyClientForwardsRequestAndAuth(t *testing.T) {
	srv := &testSafetyKernelServer{
		resp: &capv1.PolicyCheckResponse{
			Decision:       capv1.DecisionType_DECISION_TYPE_ALLOW,
			Reason:         "ok",
			PolicySnapshot: "snap-1",
		},
	}
	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	req := mapper.PolicyCheckRequest{
		Topic:               "job.cordclaw.exec",
		Capability:          "cordclaw.shell-execute",
		Tool:                "exec",
		Command:             "echo hi",
		Path:                "/tmp/demo.txt",
		URL:                 "https://example.com",
		Channel:             "slack://ops",
		Agent:               "agent-1",
		Session:             "session-1",
		Model:               "gpt-x",
		AllowedTools:        []string{"web_fetch", "exec"},
		AllowedCapabilities: []string{"cordclaw.web-fetch", "cordclaw.shell-execute"},
		RiskTags:            []string{"exec", "system", "write"},
	}

	decision, err := client.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("check request failed: %v", err)
	}

	if decision.Decision != "ALLOW" {
		t.Fatalf("expected ALLOW decision, got %q", decision.Decision)
	}
	if decision.Snapshot != "snap-1" {
		t.Fatalf("expected policy snapshot to be preserved, got %q", decision.Snapshot)
	}
	if srv.last == nil {
		t.Fatalf("expected grpc request to be forwarded")
	}

	if got := srv.last.GetTopic(); got != req.Topic {
		t.Fatalf("expected topic %q, got %q", req.Topic, got)
	}
	if got := srv.last.GetTenant(); got != "tenant-a" {
		t.Fatalf("expected tenant-a, got %q", got)
	}
	if got := srv.last.GetJobId(); got != req.Session {
		t.Fatalf("expected session to map to job_id, got %q", got)
	}
	if got := srv.last.GetPrincipalId(); got != req.Agent {
		t.Fatalf("expected principal id %q, got %q", req.Agent, got)
	}
	if got := srv.last.GetMeta().GetCapability(); got != req.Capability {
		t.Fatalf("expected capability %q, got %q", req.Capability, got)
	}
	if got := srv.last.GetMeta().GetRiskTags(); len(got) != len(req.RiskTags) {
		t.Fatalf("expected risk tags to be forwarded")
	}
	if got := srv.last.GetLabels()["command"]; got != req.Command {
		t.Fatalf("expected command label %q, got %q", req.Command, got)
	}
	if got := srv.last.GetLabels()["allowedTools"]; got != "exec,web_fetch" {
		t.Fatalf("expected allowedTools label to be deterministic, got %q", got)
	}
	if got := srv.last.GetMeta().GetLabels()["allowedCapabilities"]; got != "cordclaw.shell-execute,cordclaw.web-fetch" {
		t.Fatalf("expected allowedCapabilities meta label to be deterministic, got %q", got)
	}

	if got := srv.lastMD.Get("x-api-key"); len(got) == 0 || got[0] != "api-key-123" {
		t.Fatalf("expected x-api-key metadata to be forwarded")
	}
}

func TestGRPCSafetyClientDecisionMapping(t *testing.T) {
	cases := []struct {
		name         string
		pbDecision   capv1.DecisionType
		expect       string
		approvalRef  string
		withApproval bool
		constraints  *capv1.PolicyConstraints
	}{
		{name: "allow", pbDecision: capv1.DecisionType_DECISION_TYPE_ALLOW, expect: "ALLOW"},
		{name: "deny", pbDecision: capv1.DecisionType_DECISION_TYPE_DENY, expect: "DENY"},
		{name: "throttle", pbDecision: capv1.DecisionType_DECISION_TYPE_THROTTLE, expect: "THROTTLE"},
		{
			name:         "require human",
			pbDecision:   capv1.DecisionType_DECISION_TYPE_REQUIRE_HUMAN,
			expect:       "REQUIRE_HUMAN",
			approvalRef:  "apr-123",
			withApproval: true,
		},
		{
			name:       "allow with constraints",
			pbDecision: capv1.DecisionType_DECISION_TYPE_ALLOW_WITH_CONSTRAINTS,
			expect:     "CONSTRAIN",
			constraints: &capv1.PolicyConstraints{
				Budgets: &capv1.BudgetConstraints{MaxRuntimeMs: 30_000},
				Sandbox: &capv1.SandboxProfile{
					Isolated:   true,
					FsReadOnly: []string{"/workspace"},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &testSafetyKernelServer{
				resp: &capv1.PolicyCheckResponse{
					Decision:         tc.pbDecision,
					Reason:           "reason",
					ApprovalRequired: tc.withApproval,
					ApprovalRef:      tc.approvalRef,
					Constraints:      tc.constraints,
					PolicySnapshot:   "snap-1",
				},
			}
			client, cleanup := newBufconnClient(t, srv)
			defer cleanup()

			decision, err := client.Check(context.Background(), mapper.PolicyCheckRequest{
				Topic:      "job.cordclaw.exec",
				Capability: "cordclaw.shell-execute",
				Tool:       "exec",
				Command:    "echo hi",
				Agent:      "agent-1",
				Session:    "session-1",
				RiskTags:   []string{"exec"},
			})
			if err != nil {
				t.Fatalf("check failed: %v", err)
			}
			if decision.Decision != tc.expect {
				t.Fatalf("expected %q, got %q", tc.expect, decision.Decision)
			}
			if tc.expect == "REQUIRE_HUMAN" && decision.ApprovalRef != tc.approvalRef {
				t.Fatalf("expected approval ref %q, got %q", tc.approvalRef, decision.ApprovalRef)
			}
			if tc.expect == "CONSTRAIN" {
				if got, ok := decision.Constraints["timeout"].(int64); !ok || got != 30 {
					t.Fatalf("expected timeout 30s in constraints, got %#v", decision.Constraints["timeout"])
				}
				if got, ok := decision.Constraints["sandbox"].(bool); !ok || !got {
					t.Fatalf("expected sandbox=true in constraints")
				}
			}
		})
	}
}

func TestMarshalDeterministicPolicyCheckRequestIgnoresSession(t *testing.T) {
	reqA := mapper.PolicyCheckRequest{
		Topic:      "job.cordclaw.exec",
		Capability: "cordclaw.shell-execute",
		Tool:       "exec",
		Command:    "echo hi",
		Agent:      "agent-1",
		Session:    "session-a",
		RiskTags:   []string{"exec", "system", "write"},
	}
	reqB := reqA
	reqB.Session = "session-b"

	left, err := MarshalDeterministicPolicyCheckRequest(reqA, "tenant-a")
	if err != nil {
		t.Fatalf("marshal left request: %v", err)
	}
	right, err := MarshalDeterministicPolicyCheckRequest(reqB, "tenant-a")
	if err != nil {
		t.Fatalf("marshal right request: %v", err)
	}

	if !bytes.Equal(left, right) {
		t.Fatalf("expected deterministic bytes to ignore session id")
	}
}

func TestMarshalDeterministicPolicyCheckRequestIncludesAllowedIntentMetadata(t *testing.T) {
	reqA := mapper.PolicyCheckRequest{
		Topic:               "job.cordclaw.cron-create",
		Capability:          "cordclaw.schedule-create",
		Tool:                "cron.create",
		Agent:               "agent-1",
		Session:             "session-a",
		CronJobID:           "cron-7",
		AllowedTools:        []string{"web_fetch"},
		AllowedCapabilities: []string{"cordclaw.web-fetch"},
		RiskTags:            []string{"autonomy", "schedule", "write"},
	}
	reqB := reqA
	reqB.AllowedTools = []string{"exec"}

	left, err := MarshalDeterministicPolicyCheckRequest(reqA, "tenant-a")
	if err != nil {
		t.Fatalf("marshal left request: %v", err)
	}
	right, err := MarshalDeterministicPolicyCheckRequest(reqB, "tenant-a")
	if err != nil {
		t.Fatalf("marshal right request: %v", err)
	}

	if bytes.Equal(left, right) {
		t.Fatalf("expected deterministic bytes to include allowed intent metadata")
	}
}
