package config

import (
	"testing"
	"time"
)

func TestLoadFromEnvCronDecisionStoreDefaultsToBolt(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.CronDecisionStore != "bolt" {
		t.Fatalf("CronDecisionStore = %q, want bolt", cfg.CronDecisionStore)
	}
	if cfg.CronDecisionPath != "/var/lib/cordclaw/cron-decisions.db" {
		t.Fatalf("CronDecisionPath = %q", cfg.CronDecisionPath)
	}
	if cfg.CronDecisionTTL != 24*time.Hour {
		t.Fatalf("CronDecisionTTL = %v, want 24h", cfg.CronDecisionTTL)
	}
}

func TestLoadFromEnvCronDecisionStoreAllowsExplicitMemoryForDev(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CORDCLAW_CRON_DECISION_STORE", "memory")
	t.Setenv("CORDCLAW_CRON_DECISION_TTL", "30m")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.CronDecisionStore != "memory" {
		t.Fatalf("CronDecisionStore = %q, want memory", cfg.CronDecisionStore)
	}
	if cfg.CronDecisionTTL != 30*time.Minute {
		t.Fatalf("CronDecisionTTL = %v, want 30m", cfg.CronDecisionTTL)
	}
}

func TestLoadFromEnvCronDecisionStoreRejectsInvalidBackend(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CORDCLAW_CRON_DECISION_STORE", "redis")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatalf("expected invalid cron decision store backend to fail")
	}
}

func TestLoadFromEnvCronDecisionStoreRejectsInvalidTTL(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("CORDCLAW_CRON_DECISION_TTL", "eventually")

	if _, err := LoadFromEnv(); err == nil {
		t.Fatalf("expected invalid cron decision ttl to fail")
	}
}

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDCLAW_API_KEY", "test-api-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-test")
}
