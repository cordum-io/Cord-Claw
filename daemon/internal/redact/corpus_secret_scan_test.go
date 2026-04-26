package redact

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type gitleaksFinding struct {
	RuleID    string `json:"RuleID"`
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

func TestBenignCorpusContainsNoRealSecrets(t *testing.T) {
	t.Parallel()

	findings := scanWithGitleaks(t, filepath.Join("testdata", "benign-prompts"))

	require.Equal(t, 0, len(findings), "gitleaks findings (file/line/rule only):\n%s", summarizeGitleaksFindings(findings))
}

func TestBenignCorpusScanner_FailsOnSecret(t *testing.T) {
	t.Parallel()

	fixtureDir := t.TempDir()
	fixturePath := filepath.Join(fixtureDir, "has_real_pattern.txt")
	fakeSlackToken := strings.Join([]string{"xoxb", "123456789012", "123456789012", "abcdefghijklmnopqrstuvwx"}, "-")
	if err := os.WriteFile(fixturePath, []byte("example fake test fixture: "+fakeSlackToken+"\n"), 0o600); err != nil {
		t.Fatalf("write gitleaks negative fixture: %v", err)
	}

	findings := scanWithGitleaks(t, fixtureDir)

	require.Equal(t, true, len(findings) > 0, "expected gitleaks to detect the deliberate fake fixture")
}

func scanWithGitleaks(t *testing.T, source string) []gitleaksFinding {
	t.Helper()

	gitleaksPath, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Skip("gitleaks not installed; CI step ensures coverage")
	}

	sourceAbs, err := filepath.Abs(source)
	if err != nil {
		t.Fatalf("resolve gitleaks source path: %v", err)
	}

	reportPath := filepath.Join(t.TempDir(), "gitleaks-report.json")
	cmd := exec.Command(
		gitleaksPath,
		"detect",
		"--no-git",
		"--redact",
		"--source", sourceAbs,
		"--report-format", "json",
		"--report-path", reportPath,
		"--exit-code", "0",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gitleaks scan failed: %v\n%s", err, sanitizeGitleaksOutput(output))
	}

	report, err := os.ReadFile(reportPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read gitleaks report: %v", err)
	}
	if len(strings.TrimSpace(string(report))) == 0 {
		return nil
	}

	var findings []gitleaksFinding
	if err := json.Unmarshal(report, &findings); err != nil {
		t.Fatalf("parse gitleaks report: %v", err)
	}
	return findings
}

func summarizeGitleaksFindings(findings []gitleaksFinding) string {
	rows := make([]string, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, fmt.Sprintf("%s:%d-%d:%s", filepath.ToSlash(finding.File), finding.StartLine, finding.EndLine, finding.RuleID))
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

func sanitizeGitleaksOutput(output []byte) string {
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimSpace(line)
	}
	return strings.Join(lines, "\n")
}
