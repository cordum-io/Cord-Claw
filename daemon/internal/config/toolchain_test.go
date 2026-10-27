package config

import (
	"go/version"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildToolchainsFollowDaemonModule(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", "..", ".."))
	mod, err := os.ReadFile(filepath.Join(root, "daemon", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var minimum, toolchain string
	for _, line := range strings.Split(string(mod), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "go":
			minimum = "go" + fields[1]
		case "toolchain":
			toolchain = fields[1]
		}
	}
	if !version.IsValid(minimum) {
		t.Fatalf("invalid module Go requirement %q", minimum)
	}
	if !version.IsValid(toolchain) || version.Compare(toolchain, minimum) < 0 {
		t.Errorf("tested toolchain %q must meet module requirement %s", toolchain, minimum)
	}
	for _, name := range []string{"ci.yml", "codeql.yml", "dlp-security.yml", "release.yml"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
			if err != nil {
				t.Fatal(err)
			}
			for _, problem := range workflowToolchainErrors(name, data) {
				t.Error(problem)
			}
		})
	}
	data, err := os.ReadFile(filepath.Join(root, "daemon", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	want := "golang:" + strings.TrimPrefix(toolchain, "go") + "-alpine"
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "FROM" && strings.HasPrefix(fields[1], "golang:") {
			found = true
			if fields[1] != want {
				t.Errorf("Docker builder %q must match tested toolchain %q", fields[1], want)
			}
		}
	}
	if !found {
		t.Error("missing Go Docker builder")
	}
}

func workflowToolchainErrors(name string, data []byte) []string {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string         `yaml:"uses"`
				With map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return []string{err.Error()}
	}
	var problems []string
	daemonFound := false
	for jobID, job := range workflow.Jobs {
		policyParser := name == "ci.yml" && jobID == "policy-templates"
		setupFound := false
		for i, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
				continue
			}
			setupFound = true
			module, checksum := "daemon/go.mod", "daemon/go.sum"
			if policyParser {
				// This job builds Cordum's parser in a separate checkout;
				// it must use that module's toolchain, not the daemon's.
				module, checksum = "cordum/go.mod", "cordum/go.sum"
				checkoutFound := false
				for _, prior := range job.Steps[:i] {
					if strings.HasPrefix(prior.Uses, "actions/checkout@") &&
						prior.With["repository"] == "cordum-io/cordum" &&
						prior.With["path"] == "cordum" &&
						prior.With["ref"] == "${{ steps.cordum.outputs.ref }}" {
						checkoutFound = true
					}
				}
				if !checkoutFound {
					problems = append(problems, "policy-templates must first check out cordum-io/cordum at steps.cordum.outputs.ref into cordum")
				}
			} else {
				daemonFound = true
			}
			if step.With["go-version-file"] != module || step.With["cache-dependency-path"] != checksum || step.With["go-version"] != nil {
				problems = append(problems, name+"/"+jobID+": setup-go must read "+module+" and "+checksum+" without an overriding version")
			}
		}
		if policyParser && !setupFound {
			problems = append(problems, "missing policy-templates setup-go toolchain selection")
		}
	}
	if !daemonFound {
		problems = append(problems, "missing daemon setup-go toolchain selection")
	}
	return problems
}

func TestWorkflowToolchainContracts(t *testing.T) {
	const valid = `jobs:
  daemon:
    steps:
      - uses: actions/setup-go@v7
        with:
          go-version-file: daemon/go.mod
          cache-dependency-path: daemon/go.sum
  policy-templates:
    steps:
      - uses: actions/checkout@v7
        with:
          repository: cordum-io/cordum
          path: cordum
          ref: ${{ steps.cordum.outputs.ref }}
      - uses: actions/setup-go@v7
        with:
          go-version-file: cordum/go.mod
          cache-dependency-path: cordum/go.sum
`
	for _, tc := range []struct {
		name, workflow, old, replacement string
		valid                            bool
	}{
		{name: "separate parser module", workflow: "ci.yml", valid: true},
		{name: "daemon wrong module", workflow: "ci.yml", old: "go-version-file: daemon/go.mod", replacement: "go-version-file: cordum/go.mod"},
		{name: "daemon wrong checksum", workflow: "ci.yml", old: "cache-dependency-path: daemon/go.sum", replacement: "cache-dependency-path: cordum/go.sum"},
		{name: "unknown foreign job", workflow: "ci.yml", old: "policy-templates:", replacement: "other-parser:"},
		{name: "foreign job in other workflow", workflow: "release.yml"},
		{name: "parser wrong module", workflow: "ci.yml", old: "go-version-file: cordum/go.mod", replacement: "go-version-file: daemon/go.mod"},
		{name: "parser wrong checksum", workflow: "ci.yml", old: "cache-dependency-path: cordum/go.sum", replacement: "cache-dependency-path: daemon/go.sum"},
		{name: "parser version override", workflow: "ci.yml", old: "go-version-file: cordum/go.mod", replacement: "go-version-file: cordum/go.mod\n          go-version: '1.25.x'"},
		{name: "parser wrong repository", workflow: "ci.yml", old: "repository: cordum-io/cordum", replacement: "repository: other/cordum"},
		{name: "parser wrong checkout path", workflow: "ci.yml", old: "path: cordum", replacement: "path: other"},
		{name: "parser wrong source ref", workflow: "ci.yml", old: "ref: ${{ steps.cordum.outputs.ref }}", replacement: "ref: main"},
		{name: "parser missing checkout", workflow: "ci.yml", old: "actions/checkout@v7", replacement: "actions/setup-node@v7"},
		{name: "parser missing setup", workflow: "ci.yml", old: "uses: actions/setup-go@v7\n        with:\n          go-version-file: cordum/go.mod", replacement: "uses: actions/setup-node@v7\n        with:\n          go-version-file: cordum/go.mod"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := valid
			if tc.old != "" {
				data = strings.Replace(data, tc.old, tc.replacement, 1)
			}
			problems := workflowToolchainErrors(tc.workflow, []byte(data))
			if gotValid := len(problems) == 0; gotValid != tc.valid {
				t.Fatalf("valid=%t, want %t; problems: %v", gotValid, tc.valid, problems)
			}
		})
	}
}
