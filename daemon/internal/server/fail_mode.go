package server

import (
	"log/slog"
	"strings"
)

// failModeTagPriority lists the canonical action-class tags emitted by
// internal/mapper/openclaw.go in most-restrictive-first order. Resolution
// walks this list and the FIRST tag that appears in the request's RiskTags
// wins, regardless of whether it has an explicit fail-open opt-in. That
// guarantees rail #2: any tag implying mutation/exec/external delivery
// outranks a co-occurring read tag, so a fail-open opt-in cannot relax a
// concurrently-tagged write.
var failModeTagPriority = []string{
	"exec",
	"write",
	"messaging",
	"schedule",
	"browser",
	"read",
}

// actionTags is the canonical set of tags admissible as keys in
// CORDCLAW_FAIL_MODE_BY_ACTION. Anything outside this set is silently
// ignored at lookup time but warned about at construction time so
// operators can correct typos before they matter in production.
var actionTags = map[string]struct{}{
	"exec":      {},
	"write":     {},
	"messaging": {},
	"schedule":  {},
	"browser":   {},
	"read":      {},
}

// defaultFailModeByAction is the conservative-default table per task rail #2:
// only entries that explicitly opt in to fail-open appear here. Every other
// canonical tag — and any unknown tag — falls through to fail-closed.
var defaultFailModeByAction = map[string]string{
	"read": "open",
}

// failModeFor returns the effective fail-mode ("open" or "closed") that
// should apply when the gateway is unreachable for the given request risk
// tags. Uniform configuration ("open"/"closed") bypasses the per-action
// table for backward compatibility; only the "graduated" mode (and any
// unrecognised value) consults the table.
func (h *Handler) failModeFor(tags []string) string {
	switch h.cfg.FailMode {
	case "open":
		return "open"
	case "closed":
		return "closed"
	}

	requested := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		requested[tag] = struct{}{}
	}

	merged := mergedFailModeTable(h.cfg.FailModeByAction)

	for _, tag := range failModeTagPriority {
		if _, ok := requested[tag]; !ok {
			continue
		}
		if mode, present := merged[tag]; present {
			return mode
		}
		// Tag is in the canonical priority list but has no opt-in; the
		// default for any restrictive tag is fail-closed.
		return "closed"
	}
	return "closed"
}

// mergedFailModeTable overlays the operator's CORDCLAW_FAIL_MODE_BY_ACTION
// onto the conservative defaults. Both inputs are read-only; the result is
// a fresh map safe to mutate.
func mergedFailModeTable(override map[string]string) map[string]string {
	merged := make(map[string]string, len(defaultFailModeByAction)+len(override))
	for k, v := range defaultFailModeByAction {
		merged[k] = v
	}
	for k, v := range override {
		if _, ok := actionTags[k]; !ok {
			// Unknown tag: skip silently here — warn-on-load already
			// surfaced this at constructor time.
			continue
		}
		merged[k] = v
	}
	return merged
}

// warnUnknownFailModeTags emits a slog.Warn for each CORDCLAW_FAIL_MODE_BY_ACTION
// key that isn't part of the canonical action-tag set. Called once at New() so
// operator typos surface immediately on daemon startup.
func warnUnknownFailModeTags(override map[string]string) {
	for tag := range override {
		if _, ok := actionTags[tag]; ok {
			continue
		}
		slog.Warn("cordclaw fail-mode override references unknown action tag",
			"unknown_tag", tag,
			"canonical_tags", joinSorted(actionTags),
		)
	}
}

func joinSorted(set map[string]struct{}) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	// Tiny insertion sort keeps the dependency surface bounded; the set
	// has 6 elements today and isn't going to explode.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return strings.Join(keys, ",")
}
