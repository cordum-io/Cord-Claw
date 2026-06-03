package redact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicyFile(t *testing.T) {
	t.Parallel()
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	err := os.WriteFile(policyPath, []byte(`
prompt_pii_redact:
  action: DENY
  reason: redact provider-side credential leakage in agent prompts
  include_email: true
  patterns:
    - name: CUSTOM_EMPLOYEE_ID
      regex: '\bEMP-\d{6}\b'
      placeholder: '<REDACTED-CUSTOM_EMPLOYEE_ID>'
`), 0o600)
	if err != nil {
		t.Fatalf("write policy: %v", err)
	}

	policy, err := LoadPolicyFile(policyPath)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	if policy.Action != ActionDeny {
		t.Fatalf("action = %q, want DENY", policy.Action)
	}
	if len(policy.Patterns) != 2 {
		t.Fatalf("patterns = %d, want custom + email", len(policy.Patterns))
	}

	scanner, err := NewScanner(policy.Patterns, policy.Action)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	decision, matches := scanner.Scan("employee EMP-123456 emailed security@example.com")
	if decision.Action != ActionDeny {
		t.Fatalf("decision = %q, want DENY", decision.Action)
	}
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want 2", len(matches))
	}
}

func TestLoadPolicyFileRequiresPromptPIIRedact(t *testing.T) {
	t.Parallel()
	policyPath := filepath.Join(t.TempDir(), "openclaw-safety.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	if _, err := LoadPolicyFile(policyPath); err == nil {
		t.Fatalf("expected missing prompt_pii_redact to fail")
	}
}

func TestLoadRepositoryOpenClawSafetyPolicy(t *testing.T) {
	t.Parallel()
	policyPath := filepath.Clean("../../../pack/policies/openclaw-safety.yaml")
	policy, err := LoadPolicyFile(policyPath)
	if err != nil {
		t.Fatalf("load repository policy: %v", err)
	}
	if policy.Action != ActionConstrain {
		t.Fatalf("action = %q, want CONSTRAIN", policy.Action)
	}

	scanner, err := NewScanner(policy.Patterns, policy.Action)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	decision, matches := scanner.Scan("summarize sk-TESTKEY-DONTLEAK")
	if decision.Action != ActionConstrain {
		t.Fatalf("decision = %q, want CONSTRAIN", decision.Action)
	}
	if len(matches) != 1 || matches[0].Name != "OPENAI_KEY" {
		t.Fatalf("matches = %#v, want OPENAI_KEY", matches)
	}
}
