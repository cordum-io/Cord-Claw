package policy

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DecisionAllow           = "ALLOW"
	DecisionDeny            = "DENY"
	DecisionRequireApproval = "REQUIRE_APPROVAL"
)

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
	return append([]Rule(nil), doc.Rules...), nil
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
