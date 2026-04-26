package redact

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	base64OpenAISecret        = "sk-TESTKEY-DONTLEAK"
	base64OpenAIStdEncoded    = "c2stVEVTVEtFWS1ET05UTEVBSw=="
	base64OpenAIRawURLEncoded = "c2stVEVTVEtFWS1ET05UTEVBSw"
	base64AWSAccessKey        = "AKIA" + "IOSFODNN7EXAMPLE"
)

var base64AWSAccessEncoded = base64.StdEncoding.EncodeToString([]byte(base64AWSAccessKey))

func TestScannerRedactsBase64OpenAIKeyWithStandardEncoding(t *testing.T) {
	t.Parallel()

	prompt := "summarize config token " + base64OpenAIStdEncoded + " before sending"
	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 {
		t.Fatalf("matches len = %d, want 1 (%v)", len(matches), matches)
	}
	if matches[0].Name != "OPENAI_KEY" {
		t.Fatalf("match name = %q, want OPENAI_KEY", matches[0].Name)
	}
	if got := prompt[matches[0].Start:matches[0].End]; got != base64OpenAIStdEncoded {
		t.Fatalf("match span = %q, want encoded form %q", got, base64OpenAIStdEncoded)
	}
	if !strings.Contains(decision.ModifiedPrompt, "<REDACTED-OPENAI_KEY>") {
		t.Fatalf("modified prompt %q missing OPENAI placeholder", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, base64OpenAIStdEncoded) {
		t.Fatalf("modified prompt retained encoded secret: %q", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, base64OpenAISecret) {
		t.Fatalf("modified prompt exposed decoded secret: %q", decision.ModifiedPrompt)
	}
}

func TestScannerRedactsBase64OpenAIKeyAfterAssignmentLabel(t *testing.T) {
	t.Parallel()

	prompt := "Summarize config: api_key=" + base64OpenAIStdEncoded
	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 {
		t.Fatalf("matches len = %d, want 1 (%v)", len(matches), matches)
	}
	if matches[0].Name != "OPENAI_KEY" {
		t.Fatalf("match name = %q, want OPENAI_KEY", matches[0].Name)
	}
	if got := prompt[matches[0].Start:matches[0].End]; got != base64OpenAIStdEncoded {
		t.Fatalf("match span = %q, want encoded form %q", got, base64OpenAIStdEncoded)
	}
	if strings.Contains(decision.ModifiedPrompt, base64OpenAIStdEncoded) {
		t.Fatalf("modified prompt retained encoded secret: %q", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, base64OpenAISecret) {
		t.Fatalf("modified prompt exposed decoded secret: %q", decision.ModifiedPrompt)
	}
	if !strings.Contains(decision.ModifiedPrompt, "api_key=<REDACTED-OPENAI_KEY>") {
		t.Fatalf("modified prompt = %q, want label preserved and encoded value redacted", decision.ModifiedPrompt)
	}
}

func TestScannerRedactsBase64OpenAIKeyWithURLSafeRawEncoding(t *testing.T) {
	t.Parallel()

	prompt := "summarize config token " + base64OpenAIRawURLEncoded + " before sending"
	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 {
		t.Fatalf("matches len = %d, want 1 (%v)", len(matches), matches)
	}
	if matches[0].Name != "OPENAI_KEY" {
		t.Fatalf("match name = %q, want OPENAI_KEY", matches[0].Name)
	}
	if got := prompt[matches[0].Start:matches[0].End]; got != base64OpenAIRawURLEncoded {
		t.Fatalf("match span = %q, want encoded form %q", got, base64OpenAIRawURLEncoded)
	}
	if strings.Contains(decision.ModifiedPrompt, base64OpenAIRawURLEncoded) {
		t.Fatalf("modified prompt retained encoded secret: %q", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, base64OpenAISecret) {
		t.Fatalf("modified prompt exposed decoded secret: %q", decision.ModifiedPrompt)
	}
}

func TestScannerRedactsBase64AWSAccessKey(t *testing.T) {
	t.Parallel()

	prompt := "check cloud account " + base64AWSAccessEncoded + " before sending"
	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 {
		t.Fatalf("matches len = %d, want 1 (%v)", len(matches), matches)
	}
	if matches[0].Name != "AWS_ACCESS_KEY" {
		t.Fatalf("match name = %q, want AWS_ACCESS_KEY", matches[0].Name)
	}
	if got := prompt[matches[0].Start:matches[0].End]; got != base64AWSAccessEncoded {
		t.Fatalf("match span = %q, want encoded form %q", got, base64AWSAccessEncoded)
	}
	if !strings.Contains(decision.ModifiedPrompt, "<REDACTED-AWS_ACCESS_KEY>") {
		t.Fatalf("modified prompt %q missing AWS placeholder", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, base64AWSAccessEncoded) {
		t.Fatalf("modified prompt retained encoded access key: %q", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, base64AWSAccessKey) {
		t.Fatalf("modified prompt exposed decoded access key: %q", decision.ModifiedPrompt)
	}
}

func TestScannerAllowsBase64RandomGarbage(t *testing.T) {
	t.Parallel()

	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan("decode dGhpcyBpcyBub3QgYSBzZWNyZXQ= for documentation")

	if decision.Action != ActionAllow {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionAllow)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %v, want none", matches)
	}
	if decision.ModifiedPrompt != "" {
		t.Fatalf("modified prompt = %q, want empty", decision.ModifiedPrompt)
	}
}

func TestScannerBoundsHostileManyBase64Tokens(t *testing.T) {
	t.Parallel()

	tokens := make([]string, 200)
	for i := range tokens {
		tokens[i] = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo1234567890"
	}
	prompt := strings.Join(tokens, " ")
	scanner := newBase64TestScanner(t)

	started := time.Now()
	decision, matches := scanner.Scan(prompt)
	elapsed := time.Since(started)

	if elapsed >= 100*time.Millisecond {
		t.Fatalf("scan elapsed = %s, want < 100ms", elapsed)
	}
	if decision.Action != ActionAllow {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionAllow)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %v, want none", matches)
	}
}

func TestScannerBoundsHostileSingleHugeBase64Token(t *testing.T) {
	t.Parallel()

	prompt := strings.Repeat("A", 100*1024)
	scanner := newBase64TestScanner(t)

	started := time.Now()
	decision, matches := scanner.Scan(prompt)
	elapsed := time.Since(started)

	if elapsed >= 100*time.Millisecond {
		t.Fatalf("scan elapsed = %s, want < 100ms", elapsed)
	}
	if decision.Action != ActionAllow {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionAllow)
	}
	if len(matches) != 0 {
		t.Fatalf("matches = %v, want none", matches)
	}
}

func TestScannerPreservesLiteralMatchesWhenBase64SecretAlsoPresent(t *testing.T) {
	t.Parallel()

	const literal = "sk-LITERAL-DONTLEAK"
	const encodedSecond = "c2stU0VDT05ELURPTlRMRUFL"
	prompt := "literal " + literal + " and encoded " + encodedSecond
	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 2 {
		t.Fatalf("matches len = %d, want 2 (%v)", len(matches), matches)
	}
	for i, match := range matches {
		if match.Name != "OPENAI_KEY" {
			t.Fatalf("match %d name = %q, want OPENAI_KEY", i, match.Name)
		}
	}
	if got := prompt[matches[0].Start:matches[0].End]; got != literal {
		t.Fatalf("first match span = %q, want literal %q", got, literal)
	}
	if got := prompt[matches[1].Start:matches[1].End]; got != encodedSecond {
		t.Fatalf("second match span = %q, want encoded form %q", got, encodedSecond)
	}
	if strings.Count(decision.ModifiedPrompt, "<REDACTED-OPENAI_KEY>") != 2 {
		t.Fatalf("modified prompt = %q, want two OPENAI placeholders", decision.ModifiedPrompt)
	}
	if strings.Contains(decision.ModifiedPrompt, literal) || strings.Contains(decision.ModifiedPrompt, encodedSecond) {
		t.Fatalf("modified prompt retained literal or encoded secret: %q", decision.ModifiedPrompt)
	}
}

func TestScannerNeverLogsBase64Secrets(t *testing.T) {
	var standardLog bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&standardLog)
	defer log.SetOutput(oldWriter)

	handler := &secretCaptureHandler{}
	oldDefault := slog.Default()
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(oldDefault)

	prompt := "summarize config token " + base64OpenAIStdEncoded + " before sending"
	scanner := newBase64TestScanner(t)

	decision, matches := scanner.Scan(prompt)

	if decision.Action != ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, ActionConstrain)
	}
	if len(matches) != 1 {
		t.Fatalf("matches len = %d, want 1 (%v)", len(matches), matches)
	}
	if strings.Contains(standardLog.String(), base64OpenAIStdEncoded) || strings.Contains(standardLog.String(), base64OpenAISecret) {
		t.Fatalf("standard log leaked encoded or decoded secret")
	}
	if handler.contains(base64OpenAIStdEncoded) || handler.contains(base64OpenAISecret) {
		t.Fatalf("slog records leaked encoded or decoded secret")
	}
}

func newBase64TestScanner(t *testing.T) *Scanner {
	t.Helper()

	scanner, err := NewScanner(BuiltInPatterns(), ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	return scanner
}

type secretCaptureHandler struct {
	mu      sync.Mutex
	records []string
}

func (h *secretCaptureHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *secretCaptureHandler) Handle(_ context.Context, record slog.Record) error {
	var builder strings.Builder
	builder.WriteString(record.Message)
	record.Attrs(func(attr slog.Attr) bool {
		builder.WriteString(" ")
		builder.WriteString(attr.Key)
		builder.WriteString("=")
		builder.WriteString(attr.Value.String())
		return true
	})

	h.mu.Lock()
	h.records = append(h.records, builder.String())
	h.mu.Unlock()
	return nil
}

func (h *secretCaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	child := &secretCaptureHandler{}
	child.records = make([]string, 0, len(h.records)+len(attrs))

	h.mu.Lock()
	child.records = append(child.records, h.records...)
	h.mu.Unlock()

	var builder strings.Builder
	for _, attr := range attrs {
		builder.WriteString(attr.Key)
		builder.WriteString("=")
		builder.WriteString(attr.Value.String())
		builder.WriteString(" ")
	}
	if builder.Len() > 0 {
		child.records = append(child.records, builder.String())
	}
	return child
}

func (h *secretCaptureHandler) WithGroup(name string) slog.Handler {
	child := &secretCaptureHandler{}

	h.mu.Lock()
	child.records = append(child.records, h.records...)
	h.mu.Unlock()

	if name != "" {
		child.records = append(child.records, "group="+name)
	}
	return child
}

func (h *secretCaptureHandler) contains(secret string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, record := range h.records {
		if strings.Contains(record, secret) {
			return true
		}
	}
	return false
}
