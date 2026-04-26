package redact

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Action   string
	Reason   string
	Patterns []Pattern
}

func DefaultPolicy() Policy {
	return Policy{
		Action:   ActionConstrain,
		Reason:   "redact provider-side credential leakage in agent prompts",
		Patterns: BuiltInPatterns(),
	}
}

func LoadPolicyFile(path string) (Policy, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("redact policy: read %s: %w", path, err)
	}

	var doc struct {
		PromptPIIRedact struct {
			Action       string `yaml:"action"`
			Reason       string `yaml:"reason"`
			IncludeEmail bool   `yaml:"include_email"`
			Patterns     []struct {
				Name        string `yaml:"name"`
				Regex       string `yaml:"regex"`
				Placeholder string `yaml:"placeholder"`
			} `yaml:"patterns"`
		} `yaml:"prompt_pii_redact"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return Policy{}, fmt.Errorf("redact policy: parse %s: %w", path, err)
	}

	action := strings.ToUpper(strings.TrimSpace(doc.PromptPIIRedact.Action))
	if action == "" {
		return Policy{}, fmt.Errorf("redact policy: prompt_pii_redact.action is required")
	}
	patterns := make([]Pattern, 0, len(doc.PromptPIIRedact.Patterns)+1)
	for _, pattern := range doc.PromptPIIRedact.Patterns {
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
	if doc.PromptPIIRedact.IncludeEmail {
		patterns = append(patterns, EmailPattern())
	}
	if len(patterns) == 0 {
		return Policy{}, fmt.Errorf("redact policy: prompt_pii_redact.patterns is required")
	}

	reason := strings.TrimSpace(doc.PromptPIIRedact.Reason)
	if reason == "" {
		reason = "prompt pii redaction policy"
	}
	return Policy{Action: action, Reason: reason, Patterns: patterns}, nil
}
