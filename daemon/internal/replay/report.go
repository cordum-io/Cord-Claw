package replay

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

type SourceStats struct {
	AuditEntries int `json:"audit_entries"`
	CordumJobs   int `json:"cordum_jobs"`
}

type Report struct {
	Total                int         `json:"total"`
	DecisionsUnchanged   int         `json:"decisions_unchanged"`
	WouldDeny            int         `json:"would_deny"`
	WouldRequireApproval int         `json:"would_require_approval"`
	WouldConstrain       int         `json:"would_constrain"`
	SkippedAuditOnly     int         `json:"skipped_audit_only"`
	RuleHits             []RuleHit   `json:"rule_hits"`
	Changes              []Change    `json:"changes,omitempty"`
	SourceStats          SourceStats `json:"source_stats"`
	Warnings             []string    `json:"warnings,omitempty"`
}

type Change struct {
	JobID            string `json:"job_id"`
	Topic            string `json:"topic"`
	Tenant           string `json:"tenant"`
	OriginalDecision string `json:"original_decision"`
	NewDecision      string `json:"new_decision"`
	NewRuleID        string `json:"new_rule_id,omitempty"`
	NewReason        string `json:"new_reason,omitempty"`
	Direction        string `json:"direction"`
}

type RuleHit struct {
	RuleID   string `json:"rule_id"`
	Decision string `json:"decision"`
	Count    int    `json:"count"`
}

func reportFromReplay(replay policyReplayResponse) *Report {
	report := &Report{
		Total:              replay.Summary.TotalJobs,
		DecisionsUnchanged: replay.Summary.Unchanged,
		RuleHits:           append([]RuleHit(nil), replay.RuleHits...),
		Changes:            append([]Change(nil), replay.Changes...),
		Warnings:           append([]string(nil), replay.Warnings...),
	}
	for _, change := range replay.Changes {
		switch normalizeDecision(change.NewDecision) {
		case "DENY", "THROTTLE":
			report.WouldDeny++
		case "REQUIRE_APPROVAL", "REQUIRE_HUMAN":
			report.WouldRequireApproval++
		case "ALLOW_WITH_CONSTRAINTS", "CONSTRAIN":
			report.WouldConstrain++
		}
	}
	if report.DecisionsUnchanged == 0 && report.Total >= report.WouldDeny+report.WouldRequireApproval+report.WouldConstrain {
		report.DecisionsUnchanged = report.Total - report.WouldDeny - report.WouldRequireApproval - report.WouldConstrain
	}
	sort.SliceStable(report.RuleHits, func(i, j int) bool {
		if report.RuleHits[i].Count == report.RuleHits[j].Count {
			return report.RuleHits[i].RuleID < report.RuleHits[j].RuleID
		}
		return report.RuleHits[i].Count > report.RuleHits[j].Count
	})
	return report
}

func normalizeDecision(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func (r Report) WriteHuman(w io.Writer) error {
	if _, err := fmt.Fprintf(w, "%d decisions replayed: %d unchanged, %d would deny, %d would require approval, %d would constrain, %d skipped audit-only\n",
		r.Total,
		r.DecisionsUnchanged,
		r.WouldDeny,
		r.WouldRequireApproval,
		r.WouldConstrain,
		r.SkippedAuditOnly,
	); err != nil {
		return err
	}
	if len(r.RuleHits) > 0 {
		if _, err := fmt.Fprintln(w, "Top rule hits:"); err != nil {
			return err
		}
		limit := len(r.RuleHits)
		if limit > 5 {
			limit = 5
		}
		for i := 0; i < limit; i++ {
			hit := r.RuleHits[i]
			if _, err := fmt.Fprintf(w, "- %s (%s): %d\n", hit.RuleID, hit.Decision, hit.Count); err != nil {
				return err
			}
		}
	}
	if len(r.Warnings) > 0 {
		if _, err := fmt.Fprintln(w, "Warnings:"); err != nil {
			return err
		}
		for _, warning := range r.Warnings {
			if _, err := fmt.Fprintf(w, "- %s\n", warning); err != nil {
				return err
			}
		}
	}
	return nil
}
