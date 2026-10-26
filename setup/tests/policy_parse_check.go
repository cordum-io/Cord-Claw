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
	"strings"

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
	catSSHKey   = req("job.cordclaw.exec", "exec", "remote-access", "secrets", "system", "write")
	dockerRun   = req("job.cordclaw.exec", "exec", "system", "write", "infrastructure")
	gitPush     = req("job.cordclaw.exec", "exec", "system", "write", "code-deploy")
	npmInstall  = req("job.cordclaw.exec", "exec", "system", "write", "package-install")
	printenv    = req("job.cordclaw.exec", "exec", "system", "write", "secrets")
	readFile    = req("job.cordclaw.file-read", "filesystem", "read")
	readSSHKey  = req("job.cordclaw.file-read", "filesystem", "read", "secrets", "system-config")
	writeFile   = req("job.cordclaw.file-write", "filesystem", "write")
	writeSSHKey = req("job.cordclaw.file-write", "filesystem", "write", "secrets", "system-config")
	browse      = req("job.cordclaw.browser", "network", "browser")
	browserAct  = req("job.cordclaw.browser-action", "network", "browser", "write")
	webFetch    = req("job.cordclaw.web-fetch", "network", "read")
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
	mcpOther    = tool("mcp_server", "shell")
	mcpCore     = tool("mcp_server", "filesystem")
	cmdInspect  = tool("command_family", "inspect")
	cmdReadOnly = tool("command_family", "read_only")
	cmdList     = tool("command_family", "list")
	pathOutside = tool("path_scope", "home")
	pathWork    = tool("path_scope", "workspace")
	urlOther    = tool("url_domain", "attacker.example")
	urlGitHub   = tool("url_domain", "github.com")
	readOutside = tool("command_family", "read_only", "path_scope", "home")
)

// ladderInputs cover every legacy topic and exec risk tag the templates use.
var ladderInputs = []config.PolicyInput{
	safeExec, rmRF, awsCLI, dockerRun, sshExec, catSSHKey, npmInstall, gitPush, printenv,
	readFile, readSSHKey, writeFile, writeSSHKey, browse, browserAct, webFetch, sendMsg,
	memWrite, cronCreate,
}

func req(topic string, tags ...string) config.PolicyInput {
	return config.PolicyInput{Tenant: "default", Topic: topic, Meta: config.PolicyMeta{RiskTags: tags}}
}

// msg mirrors daemon/internal/canonicalize.NormalizeMessageWrite.
func msg(pair string, tags ...string) config.PolicyInput {
	in := req("job.openclaw.message_write", append([]string{"messaging", "external", "channel_action"}, tags...)...)
	in.Labels = map[string]string{"channel_action": pair}
	return in
}

// tool is an OpenClaw tool call carrying the given label key/value pairs.
func tool(kv ...string) config.PolicyInput {
	in := req("job.openclaw.tool_call", "tool_call")
	in.Labels = map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		in.Labels[kv[i]] = kv[i+1]
	}
	return in
}

var probes = []struct {
	file  string
	input config.PolicyInput
	want  string // decision, or "decision (rule-id)" to pin the matching rule
	ms    int64  // allow_with_constraints: when set, must be sandboxed with this max_runtime_ms
}{
	// strict: approval for most writes; deny all moderate denies and cron.
	{strict, safeExec, "require_approval", 0},
	{strict, rmRF, "deny", 0},
	{strict, awsCLI, "deny", 0},
	{strict, sshExec, "deny", 0},
	{strict, catSSHKey, "deny", 0},
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
	{moderate, catSSHKey, "deny", 0},
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
	{permissive, catSSHKey, "deny", 0},
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
	// tool_call scopes: unlisted label values are denied, listed ones and calls
	// without the label fall through to the default allow; scope denies win
	// over the exact command-family allows.
	{openclaw, mcpOther, "deny", 0},
	{openclaw, mcpCore, "allow", 0},
	{openclaw, cmdInspect, "allow (openclaw-exec_command_allow-inspect)", 0},
	{openclaw, cmdReadOnly, "allow (openclaw-exec_command_allow-read_only)", 0},
	{openclaw, cmdList, "allow (openclaw-exec_command_allow-list)", 0},
	{openclaw, pathOutside, "deny", 0},
	{openclaw, pathWork, "allow", 0},
	{openclaw, urlOther, "deny", 0},
	{openclaw, urlGitHub, "allow", 0},
	{openclaw, readOutside, "deny (openclaw-file_path_scope-deny-outside)", 0},
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
		got := d.Decision
		if strings.Contains(want, " (") {
			got = fmt.Sprintf("%s (%s)", d.Decision, d.RuleID)
		}
		ok := got == want
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

	// Each profile is at least as strict as the one before it, for every input.
	rank := map[string]int{"allow": 0, "allow_with_constraints": 1, "require_approval": 2, "deny": 3}
	ladder := []string{permissive, moderate, strict}
	looser := 0
	for _, in := range ladderInputs {
		for i := 1; i < len(ladder); i++ {
			lo, hi := policies[ladder[i-1]].Evaluate(in), policies[ladder[i]].Evaluate(in)
			rankLo, okLo := rank[lo.Decision]
			rankHi, okHi := rank[hi.Decision]
			if !okLo || !okHi || rankHi < rankLo {
				looser++
				fail("%s %v: %s -> %s (%s), looser than %s -> %s (%s)", in.Topic, in.Meta.RiskTags,
					ladder[i], hi.Decision, hi.RuleID, ladder[i-1], lo.Decision, lo.RuleID)
			}
		}
	}
	if looser == 0 {
		fmt.Printf("ok   permissive <= moderate <= strict for %d inputs\n", len(ladderInputs))
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
