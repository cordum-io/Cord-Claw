package canonicalize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeBase64BlobsPipelineDecodesShortExplicitDecode(t *testing.T) {
	got := DecodeBase64Blobs("echo cm0gLXJmIC8= | base64 -d | sh")

	if got.Original != "echo cm0gLXJmIC8= | base64 -d | sh" {
		t.Fatalf("original = %q", got.Original)
	}
	if !strings.Contains(got.Canonical, "rm -rf /") {
		t.Fatalf("canonical = %q, want decoded rm -rf /", got.Canonical)
	}
	assertOperation(t, got.Operations, "base64_pipeline", "cm0gLXJmIC8=", "rm -rf /")
}

func TestDecodeBase64BlobsGenericThresholdAndInvalidInputs(t *testing.T) {
	short := DecodeBase64Blobs("echo cm0gLXJmIC8=")
	if strings.Contains(short.Canonical, "rm -rf /") {
		t.Fatalf("short non-pipeline token decoded despite threshold: %q", short.Canonical)
	}

	long := DecodeBase64Blobs("echo cm0gLXJmIC8gLXRlc3Q=")
	if !strings.Contains(long.Canonical, "rm -rf / -test") {
		t.Fatalf("long base64 token not surfaced: %q", long.Canonical)
	}
	assertOperation(t, long.Operations, "base64_blob", "cm0gLXJmIC8gLXRlc3Q=", "rm -rf / -test")

	malformed := DecodeBase64Blobs("echo not-valid-base64!!!!")
	if malformed.Canonical != malformed.Original {
		t.Fatalf("malformed input changed: %#v", malformed)
	}
}

func TestExpandShellVarsUsesLocalAssignmentsAndExplicitEnvOnly(t *testing.T) {
	t.Setenv("FOO", "from-process-env")

	local := ExpandShellVars("FOO=malicious; ${FOO} --drop")
	if !strings.Contains(local.Canonical, "malicious --drop") {
		t.Fatalf("canonical = %q, want local expansion", local.Canonical)
	}
	assertOperation(t, local.Operations, "shell_var", "FOO", "malicious")

	processEnv := ExpandShellVars("echo $FOO")
	if strings.Contains(processEnv.Canonical, "from-process-env") {
		t.Fatalf("process env leaked into canonical form: %q", processEnv.Canonical)
	}

	explicit := ExpandShellVars("echo $FOO", WithEnv(map[string]string{"FOO": "from-options"}))
	if !strings.Contains(explicit.Canonical, "from-options") {
		t.Fatalf("explicit env not expanded: %q", explicit.Canonical)
	}
}

func TestExpandShellVarsSurfacesCommandSubstitutionsWithoutExecuting(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	cmd := "echo $(rm -rf /); echo `printf pwned > " + marker + "`"

	got := ExpandShellVars(cmd)
	if !strings.Contains(got.Canonical, "rm -rf /") {
		t.Fatalf("canonical = %q, want substitution body", got.Canonical)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command substitution appears to have executed; stat err=%v", err)
	}
	assertOperation(t, got.Operations, "command_substitution", "$(rm -rf /)", "rm -rf /")
}

func TestResolveSymlinksPathContextOnly(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.sh")
	if err := os.WriteFile(target, []byte("echo safe"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "link.sh")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this filesystem: %v", err)
	}

	got := ResolveSymlinks("sh "+link, WithPathRoot(root))
	if !strings.Contains(got.Canonical, target) {
		t.Fatalf("canonical = %q, want resolved target %q", got.Canonical, target)
	}
	assertOperation(t, got.Operations, "symlink_resolved", link, target)

	denied := ResolveSymlinks("cat /proc/self/environ", WithPathRoot(root))
	if strings.Contains(denied.Canonical, "environ ->") {
		t.Fatalf("denied path was resolved: %q", denied.Canonical)
	}
	assertOperationKind(t, denied.Operations, "symlink_skipped")
}

func TestNormalizeComposesCanonicalizers(t *testing.T) {
	got := Normalize("FOO=cm0gLXJmIC8=; echo ${FOO} | base64 -d | sh")
	if !strings.Contains(got.Canonical, "rm -rf /") {
		t.Fatalf("canonical = %q, want composed base64/env expansion", got.Canonical)
	}
	if got.Original == got.Canonical {
		t.Fatalf("normalize did not augment canonical form: %#v", got)
	}
}

func assertOperation(t *testing.T, ops []Operation, kind string, input string, output string) {
	t.Helper()
	for _, op := range ops {
		if op.Kind == kind && op.Input == input && op.Output == output {
			return
		}
	}
	t.Fatalf("expected operation kind=%q input=%q output=%q in %#v", kind, input, output, ops)
}

func assertOperationKind(t *testing.T, ops []Operation, kind string) {
	t.Helper()
	for _, op := range ops {
		if op.Kind == kind {
			return
		}
	}
	t.Fatalf("expected operation kind=%q in %#v", kind, ops)
}
