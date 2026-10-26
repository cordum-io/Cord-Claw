package redact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// sidecarFileName holds the prompt_pii_redact block next to the pack policy
// fragment: Cordum's policy schema rejects that key inside fragments, so
// pack/policies/openclaw-safety.yaml no longer carries it.
const sidecarFileName = "prompt-pii-redact.yaml"

type Policy struct {
	Action   string
	Reason   string
	Patterns []Pattern
}

type promptPIIRedactBlock struct {
	Action       string `yaml:"action"`
	Reason       string `yaml:"reason"`
	IncludeEmail bool   `yaml:"include_email"`
	Patterns     []struct {
		Name        string `yaml:"name"`
		Regex       string `yaml:"regex"`
		Placeholder string `yaml:"placeholder"`
	} `yaml:"patterns"`
}

func DefaultPolicy() Policy {
	return Policy{
		Action:   ActionConstrain,
		Reason:   "redact provider-side credential leakage in agent prompts",
		Patterns: BuiltInPatterns(),
	}
}

// LoadPolicyFile reads the prompt_pii_redact block from path. A file without
// the block, such as the pack's openclaw-safety.yaml that older docs pointed
// CORDCLAW_DLP_POLICY_PATH at, falls back to the sidecar file beside it.
func LoadPolicyFile(path string) (Policy, error) {
	block, err := readPromptPIIRedact(path)
	if err == nil && block == nil {
		sidecar := filepath.Join(filepath.Dir(path), sidecarFileName)
		if _, statErr := os.Stat(sidecar); statErr == nil {
			block, err = readPromptPIIRedact(sidecar)
		}
	}
	if err != nil {
		return Policy{}, err
	}
	if block == nil {
		return Policy{}, fmt.Errorf("redact policy: %s has no prompt_pii_redact block", path)
	}

	action := strings.ToUpper(strings.TrimSpace(block.Action))
	if action == "" {
		return Policy{}, fmt.Errorf("redact policy: prompt_pii_redact.action is required")
	}
	patterns := make([]Pattern, 0, len(block.Patterns)+1)
	for _, pattern := range block.Patterns {
		name := strings.TrimSpace(pattern.Name)
		regex := strings.TrimSpace(pattern.Regex)
		if name == "" || regex == "" {
			return Policy{}, fmt.Errorf("redact policy: pattern name and regex are required")
		}
		patterns = append(patterns, Pattern{
			Name:        name,
			Regex:       regex,
			Placeholder: strings.TrimSpace(pattern.Placeholder),
		})
	}
	if block.IncludeEmail {
		patterns = append(patterns, EmailPattern())
	}
	if len(patterns) == 0 {
		return Policy{}, fmt.Errorf("redact policy: prompt_pii_redact.patterns is required")
	}
	for _, pattern := range patterns {
		if err := validatePatternSafety(pattern); err != nil {
			return Policy{}, fmt.Errorf("redact policy: %w", err)
		}
	}

	reason := strings.TrimSpace(block.Reason)
	if reason == "" {
		reason = "prompt pii redaction policy"
	}
	return Policy{Action: action, Reason: reason, Patterns: patterns}, nil
}

func readPromptPIIRedact(path string) (*promptPIIRedactBlock, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("redact policy: read %s: %w", path, err)
	}
	var doc struct {
		PromptPIIRedact *promptPIIRedactBlock `yaml:"prompt_pii_redact"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("redact policy: parse %s: %w", path, err)
	}
	return doc.PromptPIIRedact, nil
}
