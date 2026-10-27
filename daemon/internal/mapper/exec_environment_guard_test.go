package mapper

import (
	"slices"
	"testing"
)

func TestMapExecEnvironmentDumpGuard(t *testing.T) {
	for _, command := range []string{
		"builtin export -p",
		"eval 'printenv'",
		"builtin declare -xp",
		"builtin -- export -p",
		"builtin builtin export -p",
		"command builtin export -p",
		"command eval '$ENV_COMMAND'",
		"eval \"$ENV_COMMAND\"",
		"env -S 'sh -c printenv'",
		"awk 'BEGIN {system(\"printenv\")}'",
		"python3 -c \"import subprocess; subprocess.run(['printenv'])\"",
		"busybox env",
		"toybox printenv",
		"sh -c \"builtin export -p\"",
	} {
		t.Run(command, func(t *testing.T) {
			request, err := Map(OpenClawAction{Tool: "exec", Command: command})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(request.RiskTags, "secrets") {
				t.Fatalf("environment dump %q got risk tags %v; expected secrets", command, request.RiskTags)
			}
		})
	}
}

func TestMapExecEnvironmentGuardPreservesBenignCommands(t *testing.T) {
	for _, command := range []string{
		"builtin export PATH=/usr/bin",
		"builtin printf hello",
		"grep -rn printenv docs/",
		"command -v env",
		"env FOO=1 node app.js",
		"docker run --env FOO=1 alpine",
	} {
		t.Run(command, func(t *testing.T) {
			request, err := Map(OpenClawAction{Tool: "exec", Command: command})
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(request.RiskTags, "secrets") {
				t.Fatalf("non-dump %q unexpectedly got secrets tag", command)
			}
		})
	}
}
