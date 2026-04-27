package policy

import (
	"reflect"
	"testing"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"gopkg.in/yaml.v3"
)

func TestPartition_ByEnforceFlag(t *testing.T) {
	rules := []Rule{
		{ID: "default-enforced", Enforce: nil},
		{ID: "explicit-enforced", Enforce: boolPtr(true)},
		{ID: "shadow-preview", Enforce: boolPtr(false)},
	}

	enforced, shadow := Partition(rules)

	assertRuleIDs(t, enforced, []string{"default-enforced", "explicit-enforced"})
	assertRuleIDs(t, shadow, []string{"shadow-preview"})
}

func TestEvaluateWithShadow_RealUnchanged_ShadowDeny_OverAllowedTraffic(t *testing.T) {
	rules := []Rule{
		{
			ID:       "real-allow-web-fetch",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network", "read"}},
			Decision: "allow",
			Reason:   "web fetch is currently allowed",
		},
		{
			ID:       "shadow-deny-web-fetch",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network", "read"}},
			Decision: "deny",
			Reason:   "future stricter network-read rule",
			Enforce:  boolPtr(false),
		},
	}

	real, events := EvaluateWithShadow(rules, webFetchEnvelope())

	if real.Action != "ALLOW" {
		t.Fatalf("real action = %q, want ALLOW; shadow deny must not affect enforcement", real.Action)
	}
	if real.Reason != "web fetch is currently allowed" {
		t.Fatalf("real reason = %q, want enforced rule reason", real.Reason)
	}
	wantEvents := []ShadowEvent{{
		RuleID:        "shadow-deny-web-fetch",
		WouldDecision: "DENY",
		WouldReason:   "future stricter network-read rule",
		HookName:      "before_tool_execution",
		Topic:         "job.openclaw.tool_call",
	}}
	if !reflect.DeepEqual(events, wantEvents) {
		t.Fatalf("shadow events = %#v, want %#v", events, wantEvents)
	}
}

func TestEvaluateWithShadow_EnforcedDeny_ShadowAllow(t *testing.T) {
	rules := []Rule{
		{
			ID:       "real-deny-secrets",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"secrets"}},
			Decision: "deny",
			Reason:   "secret access blocked",
		},
		{
			ID:       "shadow-allow-secrets",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"secrets"}},
			Decision: "allow",
			Reason:   "candidate exception would allow this",
			Enforce:  boolPtr(false),
		},
	}

	real, events := EvaluateWithShadow(rules, Envelope{
		Topic:    "job.openclaw.tool_call",
		Tool:     "read",
		HookName: "before_tool_execution",
		RiskTags: []string{"filesystem", "read", "secrets"},
	})

	if real.Action != "DENY" {
		t.Fatalf("real action = %q, want DENY from enforced rule", real.Action)
	}
	if len(events) != 1 {
		t.Fatalf("shadow event count = %d, want 1: %#v", len(events), events)
	}
	if events[0].WouldDecision != "ALLOW" || events[0].WouldReason != "candidate exception would allow this" {
		t.Fatalf("shadow event = %#v, want would ALLOW with candidate-exception reason", events[0])
	}
}

func TestEvaluateWithShadow_AllMatchingShadowRulesEmittedInOrder(t *testing.T) {
	rules := []Rule{
		{ID: "real-allow", Match: MatchSpec{Topics: []string{"job.openclaw.tool_call"}}, Decision: "allow", Reason: "real allow"},
		{ID: "shadow-deny-network", Match: MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network"}}, Decision: "deny", Reason: "would deny network", Enforce: boolPtr(false)},
		{ID: "shadow-approval-read", Match: MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"read"}}, Decision: "require_approval", Reason: "would request review", Enforce: boolPtr(false)},
	}

	real, events := EvaluateWithShadow(rules, webFetchEnvelope())

	if real.Action != "ALLOW" {
		t.Fatalf("real action = %q, want ALLOW", real.Action)
	}
	gotIDs := []string{}
	gotDecisions := []string{}
	for _, ev := range events {
		gotIDs = append(gotIDs, ev.RuleID)
		gotDecisions = append(gotDecisions, ev.WouldDecision)
	}
	if !reflect.DeepEqual(gotIDs, []string{"shadow-deny-network", "shadow-approval-read"}) {
		t.Fatalf("shadow ids = %#v, want both matching shadow rules in order", gotIDs)
	}
	if !reflect.DeepEqual(gotDecisions, []string{"DENY", "REQUIRE_APPROVAL"}) {
		t.Fatalf("shadow decisions = %#v", gotDecisions)
	}
}

func TestEvaluateWithShadow_NoShadowRules_ZeroEvents(t *testing.T) {
	rules := []Rule{
		{
			ID:       "real-allow-tool-call",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}},
			Decision: "allow",
			Reason:   "default allow",
		},
	}

	real, events := EvaluateWithShadow(rules, webFetchEnvelope())

	if real.Action != "ALLOW" {
		t.Fatalf("real action = %q, want ALLOW", real.Action)
	}
	if len(events) != 0 {
		t.Fatalf("shadow event count = %d, want 0: %#v", len(events), events)
	}
}

func TestCacheStability_ShadowDoesNotAffectKey(t *testing.T) {
	env := webFetchEnvelope()
	payloadHash := "same-deterministic-policy-request-hash"

	keyWithoutShadow := cache.KeyForHook(env.HookName, env.Tool, payloadHash)
	_ = []Rule{{ID: "real", Match: MatchSpec{Topics: []string{env.Topic}}, Decision: "allow"}}
	_ = []Rule{{ID: "real", Match: MatchSpec{Topics: []string{env.Topic}}, Decision: "allow"}, {ID: "shadow", Match: MatchSpec{Topics: []string{env.Topic}}, Decision: "deny", Enforce: boolPtr(false)}}
	keyWithShadow := cache.KeyForHook(env.HookName, env.Tool, payloadHash)

	if keyWithShadow != keyWithoutShadow {
		t.Fatalf("cache key changed after adding shadow rules: without=%q with=%q", keyWithoutShadow, keyWithShadow)
	}

	decisionCache := cache.New(1)
	decisionCache.Set(keyWithoutShadow, cache.Decision{Decision: "ALLOW", Reason: "cached real decision"}, time.Minute)

	shadowEvaluations := 0
	if _, ok := decisionCache.Get(keyWithShadow); !ok {
		shadowEvaluations++
		_, _ = EvaluateWithShadow(nil, env)
	}
	if shadowEvaluations != 0 {
		t.Fatalf("shadow evaluations on cache hit = %d, want 0", shadowEvaluations)
	}
}

func TestApprovalSafety_ShadowRequireApprovalNeverEnqueues(t *testing.T) {
	rules := []Rule{
		{
			ID:       "real-allow-web-fetch",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network", "read"}},
			Decision: "allow",
			Reason:   "traffic remains allowed",
		},
		{
			ID:       "shadow-approval-web-fetch",
			Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}, RiskTags: []string{"network", "read"}},
			Decision: "require_approval",
			Reason:   "candidate workflow would ask a human",
			Enforce:  boolPtr(false),
		},
	}

	real, events := EvaluateWithShadow(rules, webFetchEnvelope())

	if real.Action != "ALLOW" {
		t.Fatalf("real action = %q, want ALLOW", real.Action)
	}
	if RequiresApproval(real) {
		t.Fatalf("RequiresApproval(real) = true for a shadow-only approval candidate; approval must follow the real decision")
	}
	if len(events) != 1 || events[0].WouldDecision != "REQUIRE_APPROVAL" {
		t.Fatalf("events = %#v, want one shadow REQUIRE_APPROVAL event", events)
	}

	realApproval, _ := EvaluateWithShadow([]Rule{{
		ID:       "real-approval",
		Match:    MatchSpec{Topics: []string{"job.openclaw.tool_call"}},
		Decision: "require_approval",
		Reason:   "real approval rule",
	}}, webFetchEnvelope())
	if !RequiresApproval(realApproval) {
		t.Fatalf("RequiresApproval(realApproval) = false, want true for enforced approval decisions")
	}
}

func TestShadowEvent_LabelsForFutureJobEmission(t *testing.T) {
	event := ShadowEvent{
		RuleID:        "shadow-deny-web-fetch",
		WouldDecision: "DENY",
		WouldReason:   "future stricter network-read rule",
		HookName:      "before_tool_execution",
		Topic:         "job.openclaw.tool_call",
	}

	want := map[string]string{
		"cordclaw.shadow":         "true",
		"cordclaw.rule_id":        "shadow-deny-web-fetch",
		"cordclaw.would_decision": "DENY",
		"cordclaw.would_reason":   "future stricter network-read rule",
		"cordclaw.hook_name":      "before_tool_execution",
	}
	if got := event.Labels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Labels() = %#v, want %#v", got, want)
	}
}

func TestEnforce_DefaultTrueOnOmittedField(t *testing.T) {
	var doc struct {
		Rules []Rule `yaml:"rules"`
	}
	raw := []byte(`rules:
  - id: omitted-enforce-rule
    match:
      topics: [job.openclaw.tool_call]
    decision: allow
    reason: omitted enforce defaults to true
  - id: explicit-shadow-rule
    enforce: false
    match:
      topics: [job.openclaw.tool_call]
    decision: deny
    reason: explicit false is shadow
`)
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("yaml unmarshal: %v", err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("decoded rule count = %d, want 2", len(doc.Rules))
	}
	if doc.Rules[0].Enforce == nil || !*doc.Rules[0].Enforce {
		t.Fatalf("omitted enforce decoded as %#v, want pointer to true", doc.Rules[0].Enforce)
	}
	if doc.Rules[1].Enforce == nil || *doc.Rules[1].Enforce {
		t.Fatalf("explicit enforce:false decoded as %#v, want pointer to false", doc.Rules[1].Enforce)
	}
}

func assertRuleIDs(t *testing.T, rules []Rule, want []string) {
	t.Helper()
	got := make([]string, 0, len(rules))
	for _, rule := range rules {
		got = append(got, rule.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule ids = %#v, want %#v", got, want)
	}
}

func webFetchEnvelope() Envelope {
	return Envelope{
		Topic:    "job.openclaw.tool_call",
		Tool:     "web_fetch",
		HookName: "before_tool_execution",
		RiskTags: []string{"network", "read"},
		Labels:   map[string]string{"mcp_server": "browser"},
	}
}

func boolPtr(v bool) *bool {
	return &v
}
