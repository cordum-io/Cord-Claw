package config

import "testing"

func TestLoadFromEnv_DefaultEmitRateLimit(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.EmitRateLimit != 50 {
		t.Fatalf("EmitRateLimit = %v, want 50", cfg.EmitRateLimit)
	}
}

func TestLoadFromEnv_EmitRateLimitOverride(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")
	t.Setenv("CORDCLAW_EMIT_RATE_LIMIT", "10")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.EmitRateLimit != 10 {
		t.Fatalf("EmitRateLimit = %v, want 10", cfg.EmitRateLimit)
	}
}

func TestLoadFromEnv_InvalidEmitRateLimit(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")
	t.Setenv("CORDCLAW_EMIT_RATE_LIMIT", "0")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("LoadFromEnv error = nil, want invalid CORDCLAW_EMIT_RATE_LIMIT")
	}
}
