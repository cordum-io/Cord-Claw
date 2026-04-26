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

func TestScannerDetectsUnicodeObfuscatedOpenAIKeys(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		prompt       string
		obfuscated   string
		prefix       string
		suffix       string
		wantModified string
	}{
		{
			name:         "cyrillic small dze and ka prefix",
			prompt:       "café ☕ Привет ѕк-TESTKEY-DONTLEAK ✅",
			obfuscated:   "ѕк-TESTKEY-DONTLEAK",
			prefix:       "café ☕ Привет ",
			suffix:       " ✅",
			wantModified: "café ☕ Привет <REDACTED-OPENAI_KEY> ✅",
		},
		{
			name:         "fullwidth compatibility prefix",
			prompt:       "先に ｓｋ-TESTKEY-DONTLEAK を要約して",
			obfuscated:   "ｓｋ-TESTKEY-DONTLEAK",
			prefix:       "先に ",
			suffix:       " を要約して",
			wantModified: "先に <REDACTED-OPENAI_KEY> を要約して",
		},
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
			if decision.ModifiedPrompt != tc.wantModified {
				t.Fatalf("modified prompt did not preserve surrounding unicode and deterministic placeholder")
			}
			if strings.Contains(decision.ModifiedPrompt, tc.obfuscated) {
				t.Fatalf("modified prompt retained original obfuscated token")
			}
			if strings.Contains(decision.ModifiedPrompt, "sk-TESTKEY-DONTLEAK") {
				t.Fatalf("modified prompt exposed normalized token")
			}
			if len(matches) != 1 {
				t.Fatalf("matches len = %d, want 1", len(matches))
			}
			match := matches[0]
			if match.Name != "OPENAI_KEY" {
				t.Fatalf("match name = %q, want OPENAI_KEY", match.Name)
			}
			if got := tc.prompt[match.Start:match.End]; got != tc.obfuscated {
				t.Fatalf("match byte span did not map back to original obfuscated literal")
			}
			if tc.prompt[:match.Start] != tc.prefix || tc.prompt[match.End:] != tc.suffix {
				t.Fatalf("match byte span did not preserve original prefix/suffix")
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

func TestScannerRunsCustomPolicyPatternsAgainstNormalizedText(t *testing.T) {
	t.Parallel()

	scanner, err := NewScanner([]Pattern{
		{Name: "CUSTOM_SK", Regex: `sk-[A-Z-]{10,}`, Placeholder: "<REDACTED-CUSTOM_SK>"},
	}, ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	prompt := "custom policy sees ｓｋ-CUSTOM-DONTLEAK before provider"
	obfuscated := "ｓｋ-CUSTOM-DONTLEAK"

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if decision.ModifiedPrompt != "custom policy sees <REDACTED-CUSTOM_SK> before provider" {
		t.Fatalf("modified prompt did not replace original obfuscated custom-policy span")
	}
	if strings.Contains(decision.ModifiedPrompt, obfuscated) || strings.Contains(decision.ModifiedPrompt, "sk-CUSTOM-DONTLEAK") {
		t.Fatalf("modified prompt retained original or normalized custom-policy token")
	}
	if len(matches) != 1 || matches[0].Name != "CUSTOM_SK" {
		t.Fatalf("matches = %v, want CUSTOM_SK", matches)
	}
	if got := prompt[matches[0].Start:matches[0].End]; got != obfuscated {
		t.Fatalf("custom policy match span did not map to original obfuscated literal")
	}
}

func TestScannerAllowsSafeNonSecretUnicodeText(t *testing.T) {
	t.Parallel()

	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	decision, matches := scanner.Scan("café status ✅ — Привет мир — 重要な更新")

	if decision.Action != ActionAllow {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionAllow)
	}
	if decision.ModifiedPrompt != "" {
		t.Fatalf("safe unicode modified prompt = %q, want empty", decision.ModifiedPrompt)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %v, want none", matches)
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
