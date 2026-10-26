//go:build ignore

// Command policy_parse_check parses every safety policy Cord-Claw ships with
// Cordum's real parser (config.ParseSafetyPolicy, the one the Safety Kernel
// runs at startup) and probes the behavior each profile promises
// (docs/POLICY_GUIDE.md) with SafetyPolicy.Evaluate.
//
// daemon/go.mod cannot require Cordum: its module path github.com/cordum/cordum
// is not fetchable (the repo is github.com/cordum-io/cordum), it depends on a
// local-replace sdk module, and it needs a newer Go. So this file runs inside a
// Cordum checkout, the same way CI does:
//
//	cd ../cordum && go run ../Cord-Claw/setup/tests/policy_parse_check.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cordum/cordum/core/infra/config"
)

// Policies that end up loaded by the Safety Kernel: install.sh copies a
// template to config/safety.yaml, the docs copy examples/policies/*, compose
// run from setup/ mounts setup/config/safety.yaml, and the pack installs its
// two policy overlays (the gateway rejects the install if either fails to
// parse). pack/policies/prompt-pii-redact.yaml is daemon config, not a policy.
var policyGlobs = []string{
	"setup/templates/*.yaml",
	"setup/config/safety.yaml",
	"examples/policies/*.yaml",
	"pack/overlays/policy.fragment.yaml",
	"pack/policies/openclaw-safety.yaml",
}

const (
	strict     = "setup/templates/policy-strict.yaml"
	moderate   = "setup/templates/policy-moderate.yaml"
	permissive = "setup/templates/policy-permissive.yaml"
	custom     = "examples/policies/custom-moderate.yaml"
	defaults   = "setup/config/safety.yaml"
	openclaw   = "pack/policies/openclaw-safety.yaml"
)

// Inputs shaped like daemon/internal/mapper output (base tags + inferred tags).
var (
	safeExec    = req("job.cordclaw.exec", "exec", "system", "write")
	rmRF        = req("job.cordclaw.exec", "exec", "system", "write", "destructive")
	awsCLI      = req("job.cordclaw.exec", "exec", "system", "write", "cloud")
	sshExec     = req("job.cordclaw.exec", "exec", "system", "write", "remote-access")
	npmInstall  = req("job.cordclaw.exec", "exec", "system", "write", "package-install")
	printenv    = req("job.cordclaw.exec", "exec", "system", "write", "secrets")
	readFile    = req("job.cordclaw.file-read", "filesystem", "read")
	readSSHKey  = req("job.cordclaw.file-read", "filesystem", "read", "secrets", "system-config")
	writeFile   = req("job.cordclaw.file-write", "filesystem", "write")
	writeSSHKey = req("job.cordclaw.file-write", "filesystem", "write", "secrets", "system-config")
	browse      = req("job.cordclaw.browser", "network", "browser")
	sendMsg     = req("job.cordclaw.message-send", "messaging", "write", "external")
	memWrite    = req("job.cordclaw.memory-write", "memory", "write", "persistence")
	cronCreate  = req("job.cordclaw.cron-create", "schedule", "write", "autonomy")
	toolCall    = req("job.openclaw.tool_call", "tool_call")
	toolSecrets = req("job.openclaw.tool_call", "tool_call", "secrets")
	promptPII   = req("job.openclaw.prompt_build", "prompt", "prompt_pii")
	cronTurn    = req("job.openclaw.agent_start", "agent_lifecycle", "cron_fire")
	cronUnknown = req("job.openclaw.cron_fire", "cron_fire", "cron_origin_unknown")
	resultGate  = req("job.openclaw.result_gating", "result_gating")
	slackSend   = msg("slack.send", "write")
	slackDelete = msg("slack.delete", "write", "destructive")
	slackUpload = msg("slack.upload_file", "write", "exfil-risk")
	tgSend      = msg("telegram.send", "write")
)

func req(topic string, tags ...string) config.PolicyInput {
	return config.PolicyInput{Tenant: "default", Topic: topic, Meta: config.PolicyMeta{RiskTags: tags}}
}

// msg mirrors daemon/internal/canonicalize.NormalizeMessageWrite.
func msg(pair string, tags ...string) config.PolicyInput {
	in := req("job.openclaw.message_write", append([]string{"messaging", "external", "channel_action"}, tags...)...)
	in.Labels = map[string]string{"channel_action": pair}
	return in
}

var probes = []struct {
	file  string
	input config.PolicyInput
	want  string
	ms    int64 // allow_with_constraints: when set, must be sandboxed with this max_runtime_ms
}{
	// strict: approval for most writes; deny destructive, secrets, cloud infra.
	{strict, safeExec, "require_approval", 0},
	{strict, rmRF, "deny", 0},
	{strict, awsCLI, "deny", 0},
	{strict, printenv, "deny", 0},
	{strict, readSSHKey, "deny", 0},
	{strict, writeSSHKey, "deny", 0},
	{strict, readFile, "allow", 0},
	{strict, writeFile, "require_approval", 0},
	{strict, browse, "allow_with_constraints", 60000},
	{strict, sendMsg, "require_approval", 0},
	{strict, memWrite, "require_approval", 0},
	{strict, cronCreate, "deny", 0},
	// moderate: routine work allowed; approval for messaging, scheduling and
	// installs; deny destructive, cloud, remote access and secrets.
	{moderate, safeExec, "allow_with_constraints", 30000},
	{moderate, rmRF, "deny", 0},
	{moderate, awsCLI, "deny", 0},
	{moderate, sshExec, "deny", 0},
	{moderate, npmInstall, "require_approval", 0},
	{moderate, printenv, "deny", 0},
	{moderate, readSSHKey, "deny", 0},
	{moderate, writeSSHKey, "deny", 0},
	{moderate, readFile, "allow", 0},
	{moderate, writeFile, "allow", 0},
	{moderate, sendMsg, "require_approval", 0},
	{moderate, memWrite, "allow", 0},
	{moderate, cronCreate, "require_approval", 0},
	// permissive: allow most; block destructive and secrets; cloud needs approval.
	{permissive, safeExec, "allow", 0},
	{permissive, rmRF, "deny", 0},
	{permissive, printenv, "deny", 0},
	{permissive, readSSHKey, "deny", 0},
	{permissive, writeSSHKey, "deny", 0},
	{permissive, awsCLI, "require_approval", 0},
	{permissive, writeFile, "allow", 0},
	// custom-moderate example: package installs constrained instead of approved.
	{custom, npmInstall, "allow_with_constraints", 120000},
	{custom, safeExec, "allow_with_constraints", 30000},
	{custom, rmRF, "deny", 0},
	{custom, readSSHKey, "deny", 0},
	// setup/config/safety.yaml: moderate-style default for compose run in place.
	{defaults, safeExec, "allow_with_constraints", 30000},
	{defaults, rmRF, "deny", 0},
	{defaults, readSSHKey, "deny", 0},
	// pack openclaw-safety fragment: exact provider.action pairs; unlisted pairs
	// stay denied. Prompt builds are redacted by the daemon itself.
	{openclaw, slackSend, "allow", 0},
	{openclaw, slackDelete, "deny", 0},
	{openclaw, slackUpload, "deny", 0},
	{openclaw, tgSend, "deny", 0},
	{openclaw, toolSecrets, "deny", 0},
	{openclaw, toolCall, "allow", 0},
	{openclaw, promptPII, "allow_with_constraints", 0},
	{openclaw, cronTurn, "deny", 0},
	{openclaw, cronUnknown, "deny", 0},
	{openclaw, resultGate, "allow_with_constraints", 0},
}

func main() {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..")
	failed := false
	fail := func(format string, args ...any) {
		failed = true
		fmt.Printf("FAIL "+format+"\n", args...)
	}

	policies := map[string]*config.SafetyPolicy{}
	for _, glob := range policyGlobs {
		paths, _ := filepath.Glob(filepath.Join(root, glob))
		if len(paths) == 0 {
			fail("%s: no files matched", glob)
		}
		for _, path := range paths {
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			policy, err := parse(path)
			if err != nil {
				fail("%s: %v", rel, err)
				continue
			}
			policies[rel] = policy
			fmt.Printf("ok   %s parses (%d rules)\n", rel, len(policy.Rules))
		}
	}
	if failed {
		os.Exit(1)
	}

	for _, p := range probes {
		policy := policies[p.file]
		if policy == nil {
			fail("%s: not loaded by policyGlobs", p.file)
			continue
		}
		d := policy.Evaluate(p.input)
		line := fmt.Sprintf("%s: %s %v", p.file, p.input.Topic, p.input.Meta.RiskTags)
		if len(p.input.Labels) > 0 {
			line += fmt.Sprintf(" %v", p.input.Labels)
		}
		line += fmt.Sprintf(" -> %s (%s)", d.Decision, d.RuleID)
		want := p.want
		ok := d.Decision == p.want
		if p.ms != 0 {
			c := d.Constraints
			line += fmt.Sprintf(" sandbox=%v max_runtime_ms=%d", c.Sandbox.Isolated, c.Budgets.MaxRuntimeMs)
			want += fmt.Sprintf(" sandbox=true max_runtime_ms=%d", p.ms)
			ok = ok && c.Sandbox.Isolated && c.Budgets.MaxRuntimeMs == p.ms
		}
		if !ok {
			fail("%s; want %s", line, want)
			continue
		}
		fmt.Printf("ok   %s\n", line)
	}
	if failed {
		os.Exit(1)
	}
}

func parse(path string) (*config.SafetyPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	policy, err := config.ParseSafetyPolicy(data)
	if err == nil && policy == nil {
		err = fmt.Errorf("empty policy")
	}
	return policy, err
}
