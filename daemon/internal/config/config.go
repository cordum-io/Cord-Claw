package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	KernelAddr     string
	APIKey         string
	TenantID       string
	ListenAddr     string
	CacheTTL       time.Duration
	CacheMaxSize   int
	LogDecisions   bool
	FailMode       string
	KernelTLSCA    string
	KernelInsecure bool
}

func LoadFromEnv() (Config, error) {
	cfg := Config{
		KernelAddr:     strings.TrimSpace(os.Getenv("CORDCLAW_KERNEL_ADDR")),
		APIKey:         strings.TrimSpace(os.Getenv("CORDCLAW_API_KEY")),
		TenantID:       strings.TrimSpace(os.Getenv("CORDCLAW_TENANT_ID")),
		ListenAddr:     getEnvDefault("CORDCLAW_LISTEN_ADDR", "127.0.0.1:19090"),
		FailMode:       getEnvDefault("CORDCLAW_FAIL_MODE", "graduated"),
		KernelTLSCA:    strings.TrimSpace(os.Getenv("CORDCLAW_KERNEL_TLS_CA")),
		KernelInsecure: parseBoolDefault("CORDCLAW_KERNEL_INSECURE", false),
		LogDecisions:   parseBoolDefault("CORDCLAW_LOG_DECISIONS", true),
	}

	cacheTTLRaw := getEnvDefault("CORDCLAW_CACHE_TTL", "5m")
	cacheTTL, err := time.ParseDuration(cacheTTLRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid CORDCLAW_CACHE_TTL: %w", err)
	}
	cfg.CacheTTL = cacheTTL

	maxSizeRaw := getEnvDefault("CORDCLAW_CACHE_MAX_SIZE", "10000")
	maxSize, err := strconv.Atoi(maxSizeRaw)
	if err != nil || maxSize <= 0 {
		return Config{}, fmt.Errorf("invalid CORDCLAW_CACHE_MAX_SIZE: %q", maxSizeRaw)
	}
	cfg.CacheMaxSize = maxSize

	if cfg.KernelAddr == "" {
		return Config{}, fmt.Errorf("CORDCLAW_KERNEL_ADDR is required")
	}
	if cfg.APIKey == "" {
		return Config{}, fmt.Errorf("CORDCLAW_API_KEY is required")
	}
	if cfg.TenantID == "" {
		return Config{}, fmt.Errorf("CORDCLAW_TENANT_ID is required")
	}

	switch cfg.FailMode {
	case "graduated", "closed", "open":
	default:
		return Config{}, fmt.Errorf("invalid CORDCLAW_FAIL_MODE: %q", cfg.FailMode)
	}

	return cfg, nil
}

func getEnvDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseBoolDefault(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
