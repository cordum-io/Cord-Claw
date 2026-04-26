package redact

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	ActionAllow     = "ALLOW"
	ActionConstrain = "CONSTRAIN"
	ActionDeny      = "DENY"

	MaxPromptBytes = 1 << 20
)

type Pattern struct {
	Name        string
	Regex       string
	Placeholder string
	Compiled    *regexp.Regexp
}

type Decision struct {
	Action         string
	Reason         string
	ModifiedPrompt string
}

type Match struct {
	Name  string
	Start int
	End   int
}

type Scanner struct {
	patterns     []Pattern
	policyAction string
}

func NewScanner(policyPatterns []Pattern, policyAction string) (*Scanner, error) {
	action := strings.ToUpper(strings.TrimSpace(policyAction))
	switch action {
	case ActionAllow, ActionConstrain, ActionDeny:
	case "":
		action = ActionConstrain
	default:
		return nil, fmt.Errorf("redact: unknown policy action %q", policyAction)
	}

	patterns := make([]Pattern, 0, len(policyPatterns))
	for _, pattern := range policyPatterns {
		pattern.Name = strings.TrimSpace(pattern.Name)
		pattern.Regex = strings.TrimSpace(pattern.Regex)
		if pattern.Name == "" || pattern.Regex == "" {
			continue
		}
		if pattern.Placeholder == "" {
			pattern.Placeholder = "<REDACTED-" + pattern.Name + ">"
		}
		if err := validatePatternSafety(pattern); err != nil {
			return nil, err
		}
		if pattern.Compiled == nil {
			compiled, err := regexp.Compile(pattern.Regex)
			if err != nil {
				return nil, fmt.Errorf("redact: compile %s: %w", pattern.Name, err)
			}
			pattern.Compiled = compiled
		}
		patterns = append(patterns, pattern)
	}
	sort.SliceStable(patterns, func(i, j int) bool {
		return patterns[i].Name < patterns[j].Name
	})

	return &Scanner{patterns: patterns, policyAction: action}, nil
}

func (s *Scanner) Scan(prompt string) (Decision, []Match) {
	if len(prompt) > MaxPromptBytes {
		return Decision{Action: ActionDeny, Reason: "prompt_too_large"}, nil
	}
	if s == nil || s.policyAction == ActionAllow || len(s.patterns) == 0 {
		return Decision{Action: ActionAllow}, nil
	}

	normalized := normalizeForScan(prompt)
	candidates := s.candidates(normalized)
	matches := nonOverlapping(candidates)
	if len(matches) == 0 {
		return Decision{Action: ActionAllow}, nil
	}

	if s.policyAction == ActionDeny {
		return Decision{Action: ActionDeny, Reason: "prompt contains pattern " + matches[0].Name}, matches
	}

	redacted := prompt
	byName := make(map[string]Pattern, len(s.patterns))
	for _, pattern := range s.patterns {
		byName[pattern.Name] = pattern
	}
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		placeholder := "<REDACTED-" + match.Name + ">"
		if pattern, ok := byName[match.Name]; ok && pattern.Placeholder != "" {
			placeholder = pattern.Placeholder
		}
		redacted = redacted[:match.Start] + placeholder + redacted[match.End:]
	}

	return Decision{Action: ActionConstrain, Reason: "prompt redacted", ModifiedPrompt: redacted}, matches
}

func (s *Scanner) candidates(normalized normalizedPrompt) []Match {
	out := make([]Match, 0)
	for _, pattern := range s.patterns {
		for _, loc := range pattern.Compiled.FindAllStringIndex(normalized.shadow, -1) {
			if len(loc) != 2 {
				continue
			}
			if pattern.Name == "AWS_SECRET" && !hasAWSSecretContext(normalized.shadow, loc[0]) {
				continue
			}
			start, end, ok := normalized.originalRange(loc[0], loc[1])
			if !ok {
				continue
			}
			out = append(out, Match{Name: pattern.Name, Start: start, End: end})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End > out[j].End
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func nonOverlapping(candidates []Match) []Match {
	matches := make([]Match, 0, len(candidates))
	lastEnd := -1
	for _, candidate := range candidates {
		if candidate.Start < lastEnd {
			continue
		}
		matches = append(matches, candidate)
		lastEnd = candidate.End
	}
	return matches
}

func hasAWSSecretContext(prompt string, start int) bool {
	lo := start - 96
	if lo < 0 {
		lo = 0
	}
	context := strings.ToLower(prompt[lo:start])
	return strings.Contains(context, "aws_secret_access_key") || strings.Contains(context, "aws secret access key")
}
