package integration_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cordum-io/cordclaw/daemon/internal/redact"
)

type outboundRecorder struct {
	requests []recordedRequest
}

type recordedRequest struct {
	host string
	body string
}

func (r *outboundRecorder) post(host string, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r.requests = append(r.requests, recordedRequest{host: host, body: string(encoded)})
	return nil
}

func TestPromptRedactionPreventsProviderSecretLeak(t *testing.T) {
	t.Parallel()

	prompt := "Summarize this config: api_key=sk-TESTKEY-DONTLEAK"
	scanner, err := redact.NewScanner(redact.BuiltInPatterns(), redact.ActionConstrain)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	decision, matches := scanner.Scan(prompt)
	if decision.Action != redact.ActionConstrain {
		t.Fatalf("decision action = %q, want %q", decision.Action, redact.ActionConstrain)
	}
	if len(matches) != 1 {
		t.Fatalf("matches = %v, want one", matches)
	}

	recorder := &outboundRecorder{}
	body := map[string]any{
		"model":    "gpt-4.1-mini",
		"messages": []map[string]string{{"role": "user", "content": decision.ModifiedPrompt}},
	}
	if err := recorder.post("api.openai.com", body); err != nil {
		t.Fatalf("record outbound body: %v", err)
	}
	if err := recorder.post("api.anthropic.com", body); err != nil {
		t.Fatalf("record outbound body: %v", err)
	}

	for _, req := range recorder.requests {
		if strings.Contains(req.body, "sk-TESTKEY-DONTLEAK") {
			t.Fatalf("provider %s outbound body leaked secret: %s", req.host, req.body)
		}
		var parsed struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.Unmarshal([]byte(req.body), &parsed); err != nil {
			t.Fatalf("parse provider %s body: %v", req.host, err)
		}
		if len(parsed.Messages) != 1 {
			t.Fatalf("provider %s message count = %d, want 1", req.host, len(parsed.Messages))
		}
		if !strings.Contains(parsed.Messages[0].Content, "<REDACTED-OPENAI_KEY>") {
			t.Fatalf("provider %s outbound content missing redaction placeholder: %s", req.host, parsed.Messages[0].Content)
		}
	}
}
