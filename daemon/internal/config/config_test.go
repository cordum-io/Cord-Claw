package config

import (
	"strings"
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

// requiredEnv sets the bare-minimum env vars so LoadFromEnv reaches the
// FailModeByAction branch instead of erroring on missing core values.
func requiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CORDCLAW_KERNEL_ADDR", "127.0.0.1:50051")
	t.Setenv("CORDCLAW_API_KEY", "test-key")
	t.Setenv("CORDCLAW_TENANT_ID", "tenant-test")
}

func TestLoadFromEnv_FailModeByAction_InvalidJSON_FailsStartup(t *testing.T) {
	requiredEnv(t)
	t.Setenv("CORDCLAW_FAIL_MODE", "graduated")
	t.Setenv("CORDCLAW_FAIL_MODE_BY_ACTION", "{not-json")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatalf("expected LoadFromEnv error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "CORDCLAW_FAIL_MODE_BY_ACTION") {
		t.Fatalf("error = %q, want substring %q", err, "CORDCLAW_FAIL_MODE_BY_ACTION")
	}
}

func TestLoadFromEnv_FailModeByAction_InvalidValue_FailsStartup(t *testing.T) {
	requiredEnv(t)
	t.Setenv("CORDCLAW_FAIL_MODE", "graduated")
	t.Setenv("CORDCLAW_FAIL_MODE_BY_ACTION", `{"read":"yolo"}`)

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatalf("expected LoadFromEnv error for invalid value 'yolo', got nil")
	}
	if !strings.Contains(err.Error(), "yolo") && !strings.Contains(err.Error(), "open") {
		t.Fatalf("error = %q, want it to mention the invalid value or expected vocabulary", err)
	}
}

func TestLoadFromEnv_FailModeByAction_ValidJSON_Loads(t *testing.T) {
	requiredEnv(t)
	t.Setenv("CORDCLAW_FAIL_MODE", "graduated")
	t.Setenv("CORDCLAW_FAIL_MODE_BY_ACTION", `{"browser":"open","read":"closed"}`)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if got, want := cfg.FailModeByAction["browser"], "open"; got != want {
		t.Fatalf("FailModeByAction[browser] = %q, want %q", got, want)
	}
	if got, want := cfg.FailModeByAction["read"], "closed"; got != want {
		t.Fatalf("FailModeByAction[read] = %q, want %q", got, want)
	}
}

func TestLoadFromEnv_FailModeByAction_EmptyEnv_NilMap(t *testing.T) {
	requiredEnv(t)
	t.Setenv("CORDCLAW_FAIL_MODE", "graduated")
	t.Setenv("CORDCLAW_FAIL_MODE_BY_ACTION", "")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	if cfg.FailModeByAction != nil && len(cfg.FailModeByAction) != 0 {
		t.Fatalf("FailModeByAction = %v, want nil/empty for unset env", cfg.FailModeByAction)
	}
}
