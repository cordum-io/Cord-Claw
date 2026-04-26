package replay

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	maxReplayRange = 7 * 24 * time.Hour
	defaultMaxJobs = 100
	maxJobsLimit   = 1000
	maxBodyBytes   = 4 << 20
)

type Options struct {
	Since                  time.Time
	Until                  time.Time
	Tenant                 string
	MaxJobs                int
	CandidatePolicyPath    string
	CandidatePolicyContent string
	DaemonURL              string
	CordumURL              string
	APIKey                 string
	HTTPClient             *http.Client
}

func (o Options) Validate() error {
	if o.Since.IsZero() {
		return fmt.Errorf("since is required")
	}
	if o.Until.IsZero() {
		return fmt.Errorf("until is required")
	}
	if !o.Since.Before(o.Until) {
		return fmt.Errorf("since must be before until")
	}
	if o.Until.Sub(o.Since) > maxReplayRange {
		return fmt.Errorf("time range exceeds maximum of 7 days")
	}
	if strings.TrimSpace(o.DaemonURL) == "" {
		return fmt.Errorf("daemon URL is required")
	}
	if strings.TrimSpace(o.CordumURL) == "" {
		return fmt.Errorf("Cordum URL is required")
	}
	if strings.TrimSpace(o.CandidatePolicyContent) == "" && strings.TrimSpace(o.CandidatePolicyPath) == "" {
		return fmt.Errorf("candidate policy content or path is required")
	}
	if o.MaxJobs < 0 {
		return fmt.Errorf("max jobs must be non-negative")
	}
	if o.MaxJobs > maxJobsLimit {
		return fmt.Errorf("max jobs exceeds maximum of %d", maxJobsLimit)
	}
	return nil
}

func (o Options) candidateContent() (string, error) {
	if content := strings.TrimSpace(o.CandidatePolicyContent); content != "" {
		return o.CandidatePolicyContent, nil
	}
	path := strings.TrimSpace(o.CandidatePolicyPath)
	if path == "" {
		return "", fmt.Errorf("candidate policy content or path is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read candidate policy: %w", err)
	}
	return string(b), nil
}

type Runner struct {
	options Options
	client  *http.Client
}

func NewRunner(options Options) *Runner {
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Runner{options: options, client: client}
}

func (r *Runner) Run(ctx context.Context) (*Report, error) {
	if err := r.options.Validate(); err != nil {
		return nil, err
	}
	candidate, err := r.options.candidateContent()
	if err != nil {
		return nil, err
	}
	if r.options.MaxJobs == 0 {
		r.options.MaxJobs = defaultMaxJobs
	}
	if strings.TrimSpace(r.options.Tenant) == "" {
		r.options.Tenant = "default"
	}

	audit, err := r.fetchAudit(ctx)
	if err != nil {
		return nil, err
	}
	jobs, err := r.fetchJobs(ctx)
	if err != nil {
		return nil, err
	}
	replay, err := r.runPolicyReplay(ctx, candidate)
	if err != nil {
		return nil, err
	}

	report := reportFromReplay(replay)
	report.SourceStats = SourceStats{AuditEntries: len(audit.Decisions), CordumJobs: len(jobs.Items)}
	if len(audit.Decisions) > len(jobs.Items) {
		report.SkippedAuditOnly = len(audit.Decisions) - len(jobs.Items)
		if report.SkippedAuditOnly > 0 {
			report.Warnings = append(report.Warnings, fmt.Sprintf("%d audit-only entries skipped", report.SkippedAuditOnly))
		}
	}
	return report, nil
}
