package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const patternLintSecretSample = "sk-TESTKEY-DONTLEAK"

func TestLoadPolicyFileRejectsUnsafePatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		regex  string
		reason string
	}{
		{name: "BROAD_DOT_STAR", regex: `.*`, reason: "overly broad"},
		{name: "BROAD_DOT_PLUS", regex: `.+`, reason: "overly broad"},
		{name: "BROAD_ANCHORED_DOT_STAR", regex: `^.*$`, reason: "overly broad"},
		{name: "BROAD_DOTALL_DOT_STAR", regex: `(?s).*`, reason: "overly broad"},
		{name: "EMPTY_STAR", regex: `a*`, reason: "matches empty string"},
		{name: "EMPTY_OPTIONAL_PREFIX", regex: `(?:sk-)?`, reason: "matches empty string"},
		{name: "NESTED_PLUS", regex: `(a+)+$`, reason: "nested quantifier"},
		{name: "NESTED_CLASS", regex: `([A-Za-z]+)*`, reason: "nested quantifier"},
		{name: "NESTED_ANY", regex: `(.*)+`, reason: "nested quantifier"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			policyPath := writePolicyFile(t, tt.name, tt.regex)
			_, err := LoadPolicyFile(policyPath)
			if err == nil {
				t.Fatalf("LoadPolicyFile(%q) succeeded, want unsafe-pattern error", tt.regex)
			}
			message := err.Error()
			if !strings.Contains(message, tt.name) {
				t.Fatalf("error %q missing pattern name %q", message, tt.name)
			}
			if !strings.Contains(message, tt.reason) {
				t.Fatalf("error %q missing reason %q", message, tt.reason)
			}
			if strings.Contains(message, patternLintSecretSample) {
				t.Fatalf("error leaked prompt sample: %q", message)
			}
		})
	}
}

func TestNewScannerRejectsUnsafePolicyPatterns(t *testing.T) {
	t.Parallel()
	_, err := NewScanner([]Pattern{{
		Name:        "BROAD_DOT_STAR",
		Regex:       `.*`,
		Placeholder: "<REDACTED-BROAD_DOT_STAR>",
	}}, ActionConstrain)
	if err == nil {
		t.Fatalf("NewScanner accepted unsafe broad wildcard pattern")
	}
	if message := err.Error(); !strings.Contains(message, "BROAD_DOT_STAR") || !strings.Contains(message, "overly broad") {
		t.Fatalf("error = %q, want pattern name and stable reason", message)
	}
}

func TestBuiltInPatternsPassSafetyLint(t *testing.T) {
	t.Parallel()
	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("built-in patterns rejected: %v", err)
	}
	decision, matches := scanner.Scan("summarize " + patternLintSecretSample)
	if decision.Action != ActionConstrain {
		t.Fatalf("decision = %q, want CONSTRAIN", decision.Action)
	}
	if len(matches) != 1 || matches[0].Name != "OPENAI_KEY" {
		t.Fatalf("matches = %#v, want OPENAI_KEY", matches)
	}
}

func writePolicyFile(t *testing.T, name, regex string) string {
	t.Helper()
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	body := "prompt_pii_redact:\n" +
		"  action: DENY\n" +
		"  reason: redact provider-side credential leakage in agent prompts\n" +
		"  include_email: false\n" +
		"  patterns:\n" +
		"    - name: " + name + "\n" +
		"      regex: '" + strings.ReplaceAll(regex, "'", "''") + "'\n" +
		"      placeholder: '<REDACTED-" + name + ">'\n"
	if err := os.WriteFile(policyPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return policyPath
}
