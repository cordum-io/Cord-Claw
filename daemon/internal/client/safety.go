package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
	"github.com/cordum-io/cordclaw/daemon/internal/mapper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcHealth "google.golang.org/grpc/health/grpc_health_v1"
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
	conn *grpc.ClientConn
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

	return &GRPCSafetyClient{conn: conn}, nil
}

func NewOfflineSafetyClient() SafetyClient {
	return &offlineSafetyClient{}
}

func (c *GRPCSafetyClient) Check(ctx context.Context, req mapper.PolicyCheckRequest) (cache.Decision, error) {
	if c.conn == nil {
		return cache.Decision{}, errors.New("safety kernel connection not initialized")
	}

	state := c.conn.GetState()
	if state == connectivity.TransientFailure || state == connectivity.Shutdown {
		return cache.Decision{}, fmt.Errorf("safety kernel unavailable: %s", state.String())
	}

	decision := evaluateDefaultPolicy(req)
	return decision, nil
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

func evaluateDefaultPolicy(req mapper.PolicyCheckRequest) cache.Decision {
	tags := make(map[string]struct{}, len(req.RiskTags))
	for _, tag := range req.RiskTags {
		tags[strings.ToLower(strings.TrimSpace(tag))] = struct{}{}
	}

	if hasAny(tags, "destructive", "remote-access", "infrastructure", "cloud") {
		return cache.Decision{
			Decision:    "REQUIRE_HUMAN",
			Reason:      "High-risk action requires explicit approval",
			ApprovalRef: "manual-review",
			Snapshot:    "local-default-v1",
		}
	}

	if hasAny(tags, "insecure-transport") {
		return cache.Decision{
			Decision: "CONSTRAIN",
			Reason:   "Non-HTTPS request constrained by policy",
			Constraints: map[string]any{
				"sandbox": true,
				"timeout": 30,
			},
			Snapshot: "local-default-v1",
		}
	}

	if req.Tool == "exec" && hasAny(tags, "package-install") {
		return cache.Decision{
			Decision: "THROTTLE",
			Reason:   "Package installation commands are rate-limited",
			Snapshot: "local-default-v1",
		}
	}

	return cache.Decision{
		Decision: "ALLOW",
		Reason:   "Action allowed by policy",
		Constraints: map[string]any{
			"sandbox": true,
			"timeout": 30,
		},
		Snapshot: "local-default-v1",
	}
}

func hasAny(tags map[string]struct{}, keys ...string) bool {
	for _, key := range keys {
		if _, ok := tags[key]; ok {
			return true
		}
	}
	return false
}
