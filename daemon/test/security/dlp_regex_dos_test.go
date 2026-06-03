//go:build security

package security_test

import (
	"strings"
	"testing"
	"time"

	"github.com/cordum-io/cordclaw/daemon/internal/redact"
)

func TestDLPRegexDoS(t *testing.T) {
	t.Parallel()

	scanner, err := redact.NewScanner(redact.BuiltInPatterns(), redact.ActionConstrain)
	if err != nil {
		t.Fatalf("NewScanner() error = %v", err)
	}

	cases := []struct {
		name  string
		input string
	}{
		{name: "openai-alternating-near-misses", input: repeatToSize("sk-A!sk-B_", 100*1024)},
		{name: "slack-bot-prefix-chains", input: repeatToSize("xoxb-"+strings.Repeat("A", 19)+"!", 100*1024)},
		{name: "aws-access-near-misses", input: repeatToSize("AKIA"+strings.Repeat("A", 15)+"!", 100*1024)},
		{name: "long-a-runs-around-boundaries", input: strings.Repeat("a", 100*1024)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			_, _ = scanner.Scan(tc.input)
			elapsed := time.Since(start)
			if elapsed >= 100*time.Millisecond {
				t.Fatalf("Scan(%s) elapsed = %s, want <100ms", tc.name, elapsed)
			}
		})
	}
}

func repeatToSize(seed string, size int) string {
	var b strings.Builder
	b.Grow(size + len(seed))
	for b.Len() < size {
		b.WriteString(seed)
	}
	out := b.String()
	return out[:size]
}
