//go:build security

package security_test

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cordum-io/cordclaw/daemon/internal/redact"
)

type expectedOutcome string

const (
	expectCatch                expectedOutcome = "CATCH"
	expectDocumentedLimitation expectedOutcome = "DOCUMENTED_LIMITATION"
)

func TestDLPBypassCorpus(t *testing.T) {
	t.Parallel()

	doc := readRedTeamDoc(t)
	cases := bypassCorpus(t)
	scanner, err := redact.NewScanner(redact.BuiltInPatterns(), redact.ActionConstrain)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}

	catchEligible := 0
	unexpectedBypasses := 0
	documentedLimitations := 0
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			requireDocRow(t, doc, tc.name)
			decision, _ := scanner.Scan(tc.payload)
			switch tc.expected {
			case expectCatch:
				catchEligible++
				if decision.Action == redact.ActionAllow {
					unexpectedBypasses++
					t.Fatalf("Scan(%s) action = %s, want non-ALLOW", tc.name, decision.Action)
				}
			case expectDocumentedLimitation:
				documentedLimitations++
				if tc.mitigationTask == "" {
					t.Fatalf("%s has no mitigation task", tc.name)
				}
				if !strings.Contains(doc, tc.mitigationTask) {
					t.Fatalf("%s mitigation task %s missing from doc", tc.name, tc.mitigationTask)
				}
				t.Logf("%s remains documented limitation via %s; scanner action=%s", tc.name, tc.mitigationTask, decision.Action)
			default:
				t.Fatalf("%s has unknown expected outcome %q", tc.name, tc.expected)
			}
		})
	}

	if len(cases) < 30 {
		t.Fatalf("bypass corpus length = %d, want >=30", len(cases))
	}
	if catchEligible == 0 {
		t.Fatalf("catch-eligible rows = 0, want >0")
	}
	if unexpectedBypasses != 0 {
		t.Fatalf("unexpected bypasses = %d/%d catch-eligible rows, want 0", unexpectedBypasses, catchEligible)
	}
	falseNegativeRate := float64(unexpectedBypasses) / float64(catchEligible)
	if falseNegativeRate > 0.05 {
		t.Fatalf("false-negative rate = %.2f%%, want <=5%%", falseNegativeRate*100)
	}
	documentedLimitationRate := float64(documentedLimitations) / float64(len(cases))
	if documentedLimitationRate > 0.80 {
		t.Fatalf("documented limitation rate = %.2f%%, want <=80%% senior-review gate", documentedLimitationRate*100)
	}
}

func TestDLPPerPatternTargetedChecks(t *testing.T) {
	t.Parallel()

	awsSecret := strings.Repeat("A", 40)
	emailScanner, err := redact.NewScanner(append(redact.BuiltInPatterns(), redact.EmailPattern()), redact.ActionConstrain)
	if err != nil {
		t.Fatalf("NewScanner(with email) error = %v", err)
	}
	defaultScanner, err := redact.NewScanner(redact.BuiltInPatterns(), redact.ActionConstrain)
	if err != nil {
		t.Fatalf("NewScanner(default) error = %v", err)
	}

	checks := []struct {
		name    string
		scanner *redact.Scanner
		payload string
		want    string
	}{
		{name: "T1-aws-secret-without-context", scanner: defaultScanner, payload: awsSecret, want: redact.ActionAllow},
		{name: "T2-aws-secret-with-context", scanner: defaultScanner, payload: "aws_secret_access_key=" + awsSecret, want: redact.ActionConstrain},
		{name: "T3-email-dotless-host", scanner: emailScanner, payload: "contact user@host for local routing", want: redact.ActionAllow},
		{name: "T4-email-valid-tld", scanner: emailScanner, payload: "contact user@example.test for help", want: redact.ActionConstrain},
	}
	doc := readRedTeamDoc(t)
	for _, tc := range checks {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			requireDocRow(t, doc, tc.name)
			decision, _ := tc.scanner.Scan(tc.payload)
			if decision.Action != tc.want {
				t.Fatalf("Scan(%s) action = %s, want %s", tc.name, decision.Action, tc.want)
			}
		})
	}
}

func TestDLPBenignCorpusFalsePositive(t *testing.T) {
	t.Parallel()

	scanner, err := redact.NewScanner(redact.BuiltInPatterns(), redact.ActionConstrain)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}

	files, err := filepath.Glob(filepath.Join(repoRoot(t), "daemon", "internal", "redact", "testdata", "benign-prompts", "*.txt"))
	if err != nil {
		t.Fatalf("glob benign corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("benign corpus files = 0, want >0")
	}

	total := 0
	falsePositives := 0
	for _, file := range files {
		fh, err := os.Open(file)
		if err != nil {
			t.Fatalf("open %s: %v", file, err)
		}
		lines := bufio.NewScanner(fh)
		for lines.Scan() {
			total++
			decision, _ := scanner.Scan(lines.Text())
			if decision.Action != redact.ActionAllow {
				falsePositives++
			}
		}
		if err := lines.Err(); err != nil {
			_ = fh.Close()
			t.Fatalf("scan %s: %v", file, err)
		}
		if err := fh.Close(); err != nil {
			t.Fatalf("close %s: %v", file, err)
		}
	}

	if total != 1000 {
		t.Fatalf("benign corpus total = %d, want 1000", total)
	}
	if falsePositives > 5 {
		t.Fatalf("false positives = %d/%d, want <=5 (0.5%%)", falsePositives, total)
	}
}

type bypassCase struct {
	name           string
	payload        string
	expected       expectedOutcome
	mitigationTask string
}

func bypassCorpus(t *testing.T) []bypassCase {
	t.Helper()

	openAIKey := "sk-TESTKEY-DONOTLEAK-1234567890"
	slackBot := "xoxb-TEST-DONOTLEAK-123456789012345"
	githubPAT := "ghp_" + strings.Repeat("A", 36)
	awsAccess := "AKIATESTKEYEXAMPLE12"
	rot13AWSSecret := strings.Repeat("N", 40)

	return []bypassCase{
		{name: "A1-unicode-cyrillic-s", payload: "ѕk-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-4c48bc3a"},
		{name: "A2-unicode-fullwidth-prefix", payload: "ｓｋ-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-4c48bc3a"},
		{name: "A3-unicode-zero-width-joiner", payload: "s\u200dk-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-4c48bc3a"},
		{name: "A4-unicode-rtl-mark", payload: "s\u202ek-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-4c48bc3a"},
		{name: "B1-base64-standard", payload: base64.StdEncoding.EncodeToString([]byte(openAIKey)), expected: expectDocumentedLimitation, mitigationTask: "task-ff10cb69"},
		{name: "B2-base64-url-safe", payload: base64.URLEncoding.EncodeToString([]byte(openAIKey)), expected: expectDocumentedLimitation, mitigationTask: "task-ff10cb69"},
		{name: "B3-base64-unpadded", payload: base64.RawStdEncoding.EncodeToString([]byte(openAIKey)), expected: expectDocumentedLimitation, mitigationTask: "task-ff10cb69"},
		{name: "B4-base64-gzip-wrapped", payload: "H4sIAAAAAAAA/" + base64.StdEncoding.EncodeToString([]byte(openAIKey)), expected: expectDocumentedLimitation, mitigationTask: "task-ff10cb69"},
		{name: "C1-rot13-openai-prefix", payload: "fx-GRFGXRL-QBABGYRNX-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "C2-rot13-slack-prefix", payload: "kbko-GRFG-QBABGYRNX-123456789012345", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "C3-rot13-github-prefix", payload: "tuc_GRFGQBABGYRNX123456789012345678901234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "C4-rot13-aws-context", payload: "njf_frperg_npprff_xrl=" + rot13AWSSecret, expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "D1-split-space-prefix", payload: "s k-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "D2-split-json-array", payload: `["s", "k-TESTKEY-DONOTLEAK-1234567890"]`, expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "D3-split-line-break", payload: "s\nk-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "D4-split-template-concat", payload: `"s" + "k-TESTKEY-DONOTLEAK-1234567890"`, expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "E1-whitespace-prefix", payload: "s k - TESTKEY - DONOTLEAK - 1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "E2-whitespace-tabs", payload: "s\tk-\tTESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "E3-whitespace-nbsp", payload: "s\u00a0k-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "E4-whitespace-thin-space", payload: "s\u2009k-TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "F1-html-decimal-entities", payload: "&#115;&#107;&#45;TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "F2-html-hex-entities", payload: "&#x73;&#x6b;&#x2d;TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "F3-html-mixed-entities", payload: "s&#107;&#45;TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "F4-html-named-separator", payload: "sk&hyphen;TESTKEY-DONOTLEAK-1234567890", expected: expectDocumentedLimitation, mitigationTask: "task-011f0cf1"},
		{name: "G1-json-escaped-openai-post-decode", payload: decodeJSONString(t, `"\u0073\u006b\u002dTESTKEY-DONOTLEAK-1234567890"`), expected: expectCatch},
		{name: "G2-json-escaped-slack-post-decode", payload: decodeJSONString(t, `"\u0078\u006f\u0078\u0062\u002dTEST-DONOTLEAK-123456789012345"`), expected: expectCatch},
		{name: "G3-json-escaped-github-post-decode", payload: decodeJSONString(t, `"\u0067\u0068\u0070\u005f`+strings.Repeat("A", 36)+`"`), expected: expectCatch},
		{name: "G4-json-escaped-aws-post-decode", payload: decodeJSONString(t, `"\u0041\u004b\u0049\u0041TESTKEYEXAMPLE12"`), expected: expectCatch},
		{name: "H1-backtick-inline-openai", payload: "`" + openAIKey + "`", expected: expectCatch},
		{name: "H2-backtick-fence-slack", payload: "```text\n" + slackBot + "\n```", expected: expectCatch},
		{name: "H3-backtick-quote-github", payload: "> `" + githubPAT + "`", expected: expectCatch},
		{name: "H4-backtick-fence-aws-access", payload: "```env\nAWS_ACCESS_KEY_ID=" + awsAccess + "\n```", expected: expectCatch},
	}
}

func decodeJSONString(t *testing.T, raw string) string {
	t.Helper()

	var out string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("json decode %q: %v", raw, err)
	}
	return out
}

func readRedTeamDoc(t *testing.T) string {
	t.Helper()

	body, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "DLP_RED_TEAM.md"))
	if err != nil {
		t.Fatalf("read DLP_RED_TEAM.md: %v", err)
	}
	return string(body)
}

func requireDocRow(t *testing.T, doc, rowID string) {
	t.Helper()

	if !strings.Contains(doc, "| "+rowID+" |") {
		t.Fatalf("DLP_RED_TEAM.md missing row %s", rowID)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
