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

func TestLoadFromEnv_DefaultShadowEmitRateLimit(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.ShadowEmitRateLimit != 5 {
		t.Fatalf("ShadowEmitRateLimit = %v, want 5", cfg.ShadowEmitRateLimit)
	}
}

func TestLoadFromEnv_ShadowEmitRateLimitOverride(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")
	t.Setenv("CORDCLAW_SHADOW_EMIT_RATE_LIMIT", "2")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.ShadowEmitRateLimit != 2 {
		t.Fatalf("ShadowEmitRateLimit = %v, want 2", cfg.ShadowEmitRateLimit)
	}
}

func TestLoadFromEnv_ShadowEmitRateLimitInvalid(t *testing.T) {
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDUM_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-a")
	t.Setenv("CORDCLAW_SHADOW_EMIT_RATE_LIMIT", "abc")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatal("LoadFromEnv error = nil, want invalid CORDCLAW_SHADOW_EMIT_RATE_LIMIT")
	}
}
