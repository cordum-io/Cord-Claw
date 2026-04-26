package redact

import (
	"strings"
	"testing"
)

func TestScannerRedactsBuiltInSecretPatterns(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		prompt      string
		patternName string
	}{
		{name: "openai key", prompt: "summarize config with sk-TESTKEY-DONTLEAK", patternName: "OPENAI_KEY"},
		{name: "slack bot token", prompt: "bot token xoxb-1234-5678-abcdefghijklmnop", patternName: "SLACK_BOT"},
		{name: "aws access key", prompt: "access key AKIAIOSFODNN7EXAMPLE", patternName: "AWS_ACCESS_KEY"},
		{name: "github pat ghp", prompt: "token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", patternName: "GITHUB_PAT"},
		{name: "github pat ghu", prompt: "token ghu_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", patternName: "GITHUB_PAT"},
		{name: "github pat ghs", prompt: "token ghs_cccccccccccccccccccccccccccccccccccc", patternName: "GITHUB_PAT"},
		{name: "aws secret guarded", prompt: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", patternName: "AWS_SECRET"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
			if err != nil {
				t.Fatalf("new scanner: %v", err)
			}

			decision, matches := scanner.Scan(tc.prompt)

			if decision.Action != ActionConstrain {
				t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
			}
			if len(matches) != 1 {
				t.Fatalf("matches len = %d, want 1 (%v)", len(matches), matches)
			}
			if matches[0].Name != tc.patternName {
				t.Fatalf("match name = %q, want %q", matches[0].Name, tc.patternName)
			}
			wantPlaceholder := "<REDACTED-" + tc.patternName + ">"
			if !strings.Contains(decision.ModifiedPrompt, wantPlaceholder) {
				t.Fatalf("modified prompt %q missing %q", decision.ModifiedPrompt, wantPlaceholder)
			}
			if strings.Contains(decision.ModifiedPrompt, tc.prompt) {
				t.Fatalf("modified prompt still contains unredacted input: %q", decision.ModifiedPrompt)
			}
		})
	}
}

func TestScannerEmailPatternIsOptIn(t *testing.T) {
	t.Parallel()

	withoutEmail, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner without email: %v", err)
	}
	decision, matches := withoutEmail.Scan("contact support@example.com for help")
	if decision.Action != ActionAllow {
		t.Fatalf("decision without email pattern = %q, want %q", decision.Action, ActionAllow)
	}
	if len(matches) != 0 {
		t.Fatalf("matches without email pattern = %v, want none", matches)
	}

	withEmail, err := NewScanner(append(BuiltInPatterns(), EmailPattern()), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner with email: %v", err)
	}
	decision, matches = withEmail.Scan("contact support@example.com for help")
	if decision.Action != ActionConstrain {
		t.Fatalf("decision with email pattern = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 || matches[0].Name != "EMAIL" {
		t.Fatalf("matches with email pattern = %v, want EMAIL", matches)
	}
	if !strings.Contains(decision.ModifiedPrompt, "<REDACTED-EMAIL>") {
		t.Fatalf("modified prompt %q missing email placeholder", decision.ModifiedPrompt)
	}
}

func TestScannerSupportsCustomPatterns(t *testing.T) {
	t.Parallel()

	patterns := append(BuiltInPatterns(), Pattern{Name: "EMPLOYEE_ID", Regex: `EMP-\d{6}`, Placeholder: "<REDACTED-EMPLOYEE_ID>"})
	scanner, err := NewScanner(patterns, ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	decision, matches := scanner.Scan("internal employee EMP-123456 is assigned")

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 || matches[0].Name != "EMPLOYEE_ID" {
		t.Fatalf("matches = %v, want EMPLOYEE_ID", matches)
	}
	if decision.ModifiedPrompt != "internal employee <REDACTED-EMPLOYEE_ID> is assigned" {
		t.Fatalf("modified prompt = %q", decision.ModifiedPrompt)
	}
}

func TestScannerDecisionShapes(t *testing.T) {
	t.Parallel()

	allowScanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new allow scanner: %v", err)
	}
	decision, matches := allowScanner.Scan("normal project status update")
	if decision.Action != ActionAllow {
		t.Fatalf("safe decision = %q, want %q", decision.Action, ActionAllow)
	}
	if decision.ModifiedPrompt != "" {
		t.Fatalf("safe modified prompt = %q, want empty", decision.ModifiedPrompt)
	}
	if len(matches) != 0 {
		t.Fatalf("safe matches = %v, want none", matches)
	}

	denyScanner, err := NewScanner(BuiltInPatterns(), ActionDeny)
	if err != nil {
		t.Fatalf("new deny scanner: %v", err)
	}
	decision, matches = denyScanner.Scan("sk-TESTKEY-DONTLEAK")
	if decision.Action != ActionDeny {
		t.Fatalf("deny decision = %q, want %q", decision.Action, ActionDeny)
	}
	if decision.Reason == "" {
		t.Fatalf("deny reason empty")
	}
	if decision.ModifiedPrompt != "" {
		t.Fatalf("deny modified prompt = %q, want empty", decision.ModifiedPrompt)
	}
	if len(matches) != 1 {
		t.Fatalf("deny matches = %v, want one", matches)
	}
}

func TestScannerRedactionIsDeterministic(t *testing.T) {
	t.Parallel()

	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	input := "OpenAI sk-TESTKEY-DONTLEAK and AWS AKIAIOSFODNN7EXAMPLE"
	firstDecision, firstMatches := scanner.Scan(input)
	secondDecision, secondMatches := scanner.Scan(input)

	if firstDecision != secondDecision {
		t.Fatalf("decisions differ: %#v vs %#v", firstDecision, secondDecision)
	}
	if len(firstMatches) != len(secondMatches) {
		t.Fatalf("match counts differ: %d vs %d", len(firstMatches), len(secondMatches))
	}
	for i := range firstMatches {
		if firstMatches[i] != secondMatches[i] {
			t.Fatalf("match %d differs: %#v vs %#v", i, firstMatches[i], secondMatches[i])
		}
	}
}

func TestScannerDoesNotTreatUnguardedBase64AsAWSSecret(t *testing.T) {
	t.Parallel()

	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	decision, matches := scanner.Scan("ordinary checksum wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in docs")
	if decision.Action != ActionAllow {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionAllow)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %v, want none", matches)
	}
}

func TestScannerDeniesOversizedPrompts(t *testing.T) {
	t.Parallel()

	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	decision, matches := scanner.Scan(strings.Repeat("a", MaxPromptBytes+1))
	if decision.Action != ActionDeny {
		t.Fatalf("oversize action = %q, want %q", decision.Action, ActionDeny)
	}
	if decision.Reason != "prompt_too_large" {
		t.Fatalf("oversize reason = %q, want prompt_too_large", decision.Reason)
	}
	if len(matches) != 0 {
		t.Fatalf("oversize matches = %v, want none", matches)
	}
}
