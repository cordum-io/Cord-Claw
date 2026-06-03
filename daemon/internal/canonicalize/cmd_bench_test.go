package canonicalize

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNormalizeNoBase64HotPathP95UnderOneMillisecond(t *testing.T) {
	command := "echo hello"
	const runs = 1000
	durations := make([]time.Duration, 0, runs)

	for i := 0; i < runs; i++ {
		start := time.Now()
		got := Normalize(command)
		durations = append(durations, time.Since(start))
		if got.Original != command {
			t.Fatalf("original = %q, want %q", got.Original, command)
		}
	}

	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(runs*95)/100]
	t.Logf("Normalize no-base64 hot path p95=%s", p95)
	if p95 > time.Millisecond {
		t.Fatalf("Normalize no-base64 p95 = %s, want <= 1ms", p95)
	}
}

func BenchmarkNormalize_NoBase64(b *testing.B) {
	benchmarkNormalize(b, "echo hello")
}

func BenchmarkNormalize_ExplicitBase64Pipeline(b *testing.B) {
	benchmarkNormalize(b, "echo cm0gLXJmIC8= | base64 -d | sh")
}

func BenchmarkNormalize_GenericLargeBlob(b *testing.B) {
	payload := base64.StdEncoding.EncodeToString([]byte("rm -rf /tmp/cordclaw-bench"))
	benchmarkNormalize(b, "echo "+payload)
}

func BenchmarkNormalize_PathTokens(b *testing.B) {
	root := b.TempDir()
	target := filepath.Join(root, "target.sh")
	if err := os.WriteFile(target, []byte("echo ok"), 0o600); err != nil {
		b.Fatalf("write target: %v", err)
	}
	link := filepath.Join(root, "link.sh")
	if err := os.Symlink(target, link); err != nil {
		b.Skipf("symlink unsupported on this filesystem: %v", err)
	}

	command := "sh " + link + " && cat /proc/self/environ"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := Normalize(command, WithPathRoot(root))
		if !strings.Contains(got.Canonical, target) {
			b.Fatalf("canonical = %q, want target %q", got.Canonical, target)
		}
	}
}

func benchmarkNormalize(b *testing.B, command string) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := Normalize(command)
		if got.Original != command {
			b.Fatalf("original = %q, want %q", got.Original, command)
		}
	}
}
