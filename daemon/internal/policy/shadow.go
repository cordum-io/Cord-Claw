package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DecisionAllow           = "ALLOW"
	DecisionDeny            = "DENY"
	DecisionRequireApproval = "REQUIRE_APPROVAL"
)

// Keep these values in lock-step with plugin/src/enforcer.ts.
const (
	maxRedactPatternLength              = 200
	maxRedactPatternQuantifiers         = 5
	maxRedactPatternAlternationSegments = 10
	canonicalDestinationDisplay         = "{file,workspace,channel,network}"
)

var canonicalDestinations = map[string]struct{}{
	"file":      {},
	"workspace": {},
	"channel":   {},
	"network":   {},
}

// MatchSpec describes the subset of Cordum safety-policy matching that the
// CordClaw shadow evaluator needs to replay locally. Empty fields are wildcards.
type MatchSpec struct {
	Topics         []string            `json:"topics,omitempty" yaml:"topics"`
	RiskTags       []string            `json:"risk_tags,omitempty" yaml:"risk_tags"`
	LabelAllowlist map[string][]string `json:"label_allowlist,omitempty" yaml:"label_allowlist"`
}

// Rule is the CordClaw-side policy DTO used by the shadow evaluator. Enforce is
// a pointer so YAML can distinguish an explicit false (shadow mode) from an
// omitted key, which defaults to enforced/true for backwards compatibility.
type Rule struct {
	ID          string         `json:"id" yaml:"id"`
	Match       MatchSpec      `json:"match" yaml:"match"`
	Decision    string         `json:"decision" yaml:"decision"`
	Reason      string         `json:"reason" yaml:"reason"`
	Constraints map[string]any `json:"constraints,omitempty" yaml:"constraints"`
	Enforce     *bool          `json:"enforce,omitempty" yaml:"enforce"`
}

// LoadRulesFile parses a Cordum safety-policy fragment and returns its rules.
// It intentionally ignores unrelated top-level primitives (for example
// prompt_pii_redact) so the CordClaw pack's openclaw-safety.yaml can serve as
// the single operator-facing policy file.
func LoadRulesFile(path string) ([]Rule, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("shadow policy: read %s: %w", path, err)
	}
	var doc struct {
		Rules []Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("shadow policy: parse %s: %w", path, err)
	}
	for i, rule := range doc.Rules {
		ruleID := strings.TrimSpace(rule.ID)
		if ruleID == "" {
			ruleID = fmt.Sprintf("<index:%d>", i)
		}
		if err := validateConstraints(rule.Constraints); err != nil {
			return nil, fmt.Errorf("shadow policy: rule %s: %w", ruleID, err)
		}
	}
	return append([]Rule(nil), doc.Rules...), nil
}

func validateConstraints(constraints map[string]any) error {
	if len(constraints) == 0 {
		return nil
	}
	if raw, ok := constraints["allowed_destinations"]; ok {
		destinations, err := stringSliceConstraint("allowed_destinations", raw)
		if err != nil {
			return err
		}
		for _, destination := range destinations {
			destination = strings.TrimSpace(destination)
			if _, ok := canonicalDestinations[destination]; !ok {
				return fmt.Errorf("allowed_destinations contains invalid value %q; canonical enum is %s", destination, canonicalDestinationDisplay)
			}
		}
	}
	if raw, ok := constraints["redact_patterns"]; ok {
		patterns, err := stringSliceConstraint("redact_patterns", raw)
		if err != nil {
			return err
		}
		for _, pattern := range patterns {
			if strings.TrimSpace(pattern) == "" {
				return fmt.Errorf("invalid redact_patterns regex")
			}
			if reason := unsafeRegexReason(pattern); reason != "" {
				return fmt.Errorf("redact_patterns regex rejected as ReDoS-unsafe (%s)", reason)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("invalid redact_patterns regex: %w", err)
			}
		}
	}
	return nil
}

func stringSliceConstraint(name string, raw any) ([]string, error) {
	switch values := raw.(type) {
	case []string:
		return append([]string(nil), values...), nil
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%s must contain only strings", name)
			}
			out = append(out, text)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be a string list", name)
	}
}

func unsafeRegexReason(pattern string) string {
	if len(pattern) > maxRedactPatternLength {
		return fmt.Sprintf("length=%d", len(pattern))
	}
	quantifiers := 0
	alternationSegments := 1
	escaped := false
	closedGroupHadQuantifier := false
	groupStack := make([]bool, 0, 8)

	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			closedGroupHadQuantifier = false
			continue
		}
		switch ch {
		case '(':
			groupStack = append(groupStack, false)
			closedGroupHadQuantifier = false
			continue
		case ')':
			closedGroupHadQuantifier = false
			if len(groupStack) > 0 {
				closedGroupHadQuantifier = groupStack[len(groupStack)-1]
				groupStack = groupStack[:len(groupStack)-1]
			}
			continue
		case '|':
			alternationSegments++
			closedGroupHadQuantifier = false
			continue
		}

		if width := quantifierWidthAt(pattern, i); width > 0 {
			quantifiers++
			if closedGroupHadQuantifier {
				return "nested-quantifier"
			}
			if len(groupStack) > 0 {
				groupStack[len(groupStack)-1] = true
			}
			closedGroupHadQuantifier = false
			i += width - 1
			continue
		}
		closedGroupHadQuantifier = false
	}

	if quantifiers > maxRedactPatternQuantifiers {
		return fmt.Sprintf("quantifier-count=%d", quantifiers)
	}
	if alternationSegments > maxRedactPatternAlternationSegments {
		return fmt.Sprintf("alternation=%d", alternationSegments)
	}
	return ""
}

func quantifierWidthAt(pattern string, index int) int {
	switch pattern[index] {
	case '*', '+', '?':
		return 1
	case '{':
	default:
		return 0
	}
	escaped := false
	for i := index + 1; i < len(pattern); i++ {
		ch := pattern[i]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '}' {
			return i - index + 1
		}
	}
	return 0
}

func (r *Rule) UnmarshalYAML(value *yaml.Node) error {
	type rawRule Rule
	var raw rawRule
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*r = Rule(raw)
	if r.Enforce == nil {
		v := true
		r.Enforce = &v
	}
	return nil
}

// Envelope is the redaction-safe subset of an OpenClaw action used for local
// rule matching. It intentionally excludes prompt/tool payload text.
type Envelope struct {
	Topic    string            `json:"topic"`
	Tool     string            `json:"tool,omitempty"`
	HookName string            `json:"hookName,omitempty"`
	RiskTags []string          `json:"riskTags,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type Decision struct {
	Action      string         `json:"action"`
	Reason      string         `json:"reason,omitempty"`
	Constraints map[string]any `json:"constraints,omitempty"`
}

// ShadowEvent is the exact structured payload that the server callback receives
// before the follow-up Cordum job-emission wire-up. It carries rule metadata
// only; never envelope payload text.
type ShadowEvent struct {
	RuleID        string `json:"rule_id"`
	WouldDecision string `json:"would_decision"`
	WouldReason   string `json:"would_reason"`
	HookName      string `json:"hook_name"`
	Topic         string `json:"topic,omitempty"`
}

func (ev ShadowEvent) Labels() map[string]string {
	return map[string]string{
		"cordclaw.shadow":         "true",
		"cordclaw.rule_id":        strings.TrimSpace(ev.RuleID),
		"cordclaw.would_decision": normalizeDecision(ev.WouldDecision),
		"cordclaw.would_reason":   strings.TrimSpace(ev.WouldReason),
		"cordclaw.hook_name":      strings.TrimSpace(ev.HookName),
	}
}

func Partition(rules []Rule) (enforced []Rule, shadow []Rule) {
	for _, rule := range rules {
		if rule.Enforce != nil && !*rule.Enforce {
			shadow = append(shadow, rule)
			continue
		}
		enforced = append(enforced, rule)
	}
	return enforced, shadow
}

func EvaluateWithShadow(rules []Rule, env Envelope) (Decision, []ShadowEvent) {
	enforced, shadow := Partition(rules)
	real := evaluateFirstMatch(enforced, env)

	events := make([]ShadowEvent, 0, len(shadow))
	for _, rule := range shadow {
		if !ruleMatches(rule.Match, env) {
			continue
		}
		events = append(events, ShadowEvent{
			RuleID:        strings.TrimSpace(rule.ID),
			WouldDecision: normalizeDecision(rule.Decision),
			WouldReason:   strings.TrimSpace(rule.Reason),
			HookName:      strings.TrimSpace(env.HookName),
			Topic:         strings.TrimSpace(env.Topic),
		})
	}
	return real, events
}

func RequiresApproval(real Decision) bool {
	return normalizeDecision(real.Action) == DecisionRequireApproval
}

func evaluateFirstMatch(rules []Rule, env Envelope) Decision {
	for _, rule := range rules {
		if !ruleMatches(rule.Match, env) {
			continue
		}
		return Decision{
			Action:      normalizeDecision(rule.Decision),
			Reason:      strings.TrimSpace(rule.Reason),
			Constraints: cloneAnyMap(rule.Constraints),
		}
	}
	return Decision{Action: DecisionDeny, Reason: "no matching enforced policy rule"}
}

func ruleMatches(match MatchSpec, env Envelope) bool {
	if len(match.Topics) > 0 && !containsString(match.Topics, env.Topic) {
		return false
	}
	if len(match.RiskTags) > 0 {
		tags := make(map[string]struct{}, len(env.RiskTags))
		for _, tag := range env.RiskTags {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags[tag] = struct{}{}
			}
		}
		for _, required := range match.RiskTags {
			if _, ok := tags[strings.TrimSpace(required)]; !ok {
				return false
			}
		}
	}
	for label, allowedValues := range match.LabelAllowlist {
		actual, ok := env.Labels[strings.TrimSpace(label)]
		if !ok || !containsString(allowedValues, actual) {
			return false
		}
	}
	return true
}

func containsString(items []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, item := range items {
		if strings.TrimSpace(item) == target {
			return true
		}
	}
	return false
}

func normalizeDecision(decision string) string {
	decision = strings.TrimSpace(decision)
	decision = strings.ReplaceAll(decision, "-", "_")
	return strings.ToUpper(decision)
}

func cloneAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
