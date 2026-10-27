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
			var workflow struct {
				Jobs map[string]struct {
					Steps []struct {
						Uses string         `yaml:"uses"`
						With map[string]any `yaml:"with"`
					} `yaml:"steps"`
				} `yaml:"jobs"`
			}
			if err := yaml.Unmarshal(data, &workflow); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, job := range workflow.Jobs {
				for _, step := range job.Steps {
					if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
						continue
					}
					found = true
					if step.With["go-version-file"] != "daemon/go.mod" || step.With["go-version"] != nil {
						t.Errorf("setup-go must read daemon/go.mod without an overriding version: %#v", step.With)
					}
				}
			}
			if !found {
				t.Error("missing setup-go toolchain selection")
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
