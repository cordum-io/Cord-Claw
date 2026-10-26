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
// overlay. Not listed yet: pack/policies/openclaw-safety.yaml, whose
// prompt_pii_redact, primitive and constraints.kind keys the schema rejects.
var policyGlobs = []string{
	"setup/templates/*.yaml",
	"setup/config/safety.yaml",
	"examples/policies/*.yaml",
	"pack/overlays/policy.fragment.yaml",
}

const (
	strict     = "setup/templates/policy-strict.yaml"
	moderate   = "setup/templates/policy-moderate.yaml"
	permissive = "setup/templates/policy-permissive.yaml"
	custom     = "examples/policies/custom-moderate.yaml"
	defaults   = "setup/config/safety.yaml"
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
)

func req(topic string, tags ...string) config.PolicyInput {
	return config.PolicyInput{Tenant: "default", Topic: topic, Meta: config.PolicyMeta{RiskTags: tags}}
}

var probes = []struct {
	file  string
	input config.PolicyInput
	want  string
	ms    int64 // allow_with_constraints only: must be sandboxed with this max_runtime_ms
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
		line := fmt.Sprintf("%s: %s %v -> %s (%s)", p.file, p.input.Topic, p.input.Meta.RiskTags, d.Decision, d.RuleID)
		want := p.want
		ok := d.Decision == p.want
		if p.want == "allow_with_constraints" {
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
