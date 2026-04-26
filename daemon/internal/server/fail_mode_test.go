package server

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/cordum-io/cordclaw/daemon/internal/cache"
	"github.com/cordum-io/cordclaw/daemon/internal/config"
)

// captureSlog redirects the default slog logger to an in-memory buffer for the
// duration of the test. Returns the buffer; restoration is registered with t.Cleanup.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := slog.Default()
	buf := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// ---------------------------------------------------------------------------
// failModeFor unit tests — graduated mode + per-action default table
// ---------------------------------------------------------------------------

func TestFailMode_DefaultTable_FailOpenForReads(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "graduated"}, &fakeSafety{})
	if got := h.failModeFor([]string{"filesystem", "read"}); got != "open" {
		t.Fatalf("failModeFor(filesystem,read) = %q, want %q", got, "open")
	}
}

func TestFailMode_DefaultTable_FailClosedForExec(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "graduated"}, &fakeSafety{})
	if got := h.failModeFor([]string{"exec", "system", "write"}); got != "closed" {
		t.Fatalf("failModeFor(exec,system,write) = %q, want %q", got, "closed")
	}
}

func TestFailMode_DefaultTable_FailClosedForWrite(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "graduated"}, &fakeSafety{})
	if got := h.failModeFor([]string{"filesystem", "write"}); got != "closed" {
		t.Fatalf("failModeFor(filesystem,write) = %q, want %q", got, "closed")
	}
}

func TestFailMode_DefaultTable_FailClosedForMessageSend(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "graduated"}, &fakeSafety{})
	if got := h.failModeFor([]string{"messaging", "write", "external"}); got != "closed" {
		t.Fatalf("failModeFor(messaging,write,external) = %q, want %q", got, "closed")
	}
}

func TestFailMode_MostRestrictiveTagWins(t *testing.T) {
	// "read" alone would fail-open; "write" alone fails-closed; both → write wins.
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "graduated"}, &fakeSafety{})
	if got := h.failModeFor([]string{"read", "write"}); got != "closed" {
		t.Fatalf("failModeFor(read,write) = %q, want %q (write beats read)", got, "closed")
	}
}

func TestFailMode_EnvOverride_PreservesDefaults(t *testing.T) {
	// Override adds browser→open without disturbing default table.
	cfg := config.Config{
		CacheMaxSize:     1,
		CacheTTL:         1,
		FailMode:         "graduated",
		FailModeByAction: map[string]string{"browser": "open"},
	}
	h := New(cfg, &fakeSafety{})

	if got := h.failModeFor([]string{"network", "browser"}); got != "open" {
		t.Fatalf("failModeFor(network,browser) override = %q, want %q", got, "open")
	}
	if got := h.failModeFor([]string{"filesystem", "read"}); got != "open" {
		t.Fatalf("failModeFor(filesystem,read) default-preserved = %q, want %q", got, "open")
	}
	if got := h.failModeFor([]string{"filesystem", "write"}); got != "closed" {
		t.Fatalf("failModeFor(filesystem,write) default-preserved = %q, want %q", got, "closed")
	}
}

func TestFailMode_EnvOverride_UnknownTag_FallsThroughToClosed(t *testing.T) {
	buf := captureSlog(t)
	cfg := config.Config{
		CacheMaxSize:     1,
		CacheTTL:         1,
		FailMode:         "graduated",
		FailModeByAction: map[string]string{"unknown_evil": "open"},
	}
	h := New(cfg, &fakeSafety{})

	// Constructor should warn about unknown tag.
	if !strings.Contains(buf.String(), "unknown_evil") {
		t.Fatalf("expected slog warn for unknown_evil tag, got: %q", buf.String())
	}
	// Lookup of an action carrying only the unknown tag falls through to default=closed.
	if got := h.failModeFor([]string{"unknown_evil"}); got != "closed" {
		t.Fatalf("failModeFor(unknown_evil) = %q, want %q", got, "closed")
	}
}

// ---------------------------------------------------------------------------
// Backward compatibility — uniform open/closed FailMode bypasses per-action table
// ---------------------------------------------------------------------------

func TestFailMode_BackCompat_OldFailModeOpen_AllOpen(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "open"}, &fakeSafety{})
	for _, tags := range [][]string{
		{"exec", "system", "write"},
		{"filesystem", "write"},
		{"messaging", "write", "external"},
	} {
		if got := h.failModeFor(tags); got != "open" {
			t.Fatalf("failModeFor(%v) FailMode=open = %q, want %q", tags, got, "open")
		}
	}
}

func TestFailMode_BackCompat_OldFailModeClosed_AllClosed(t *testing.T) {
	h := New(config.Config{CacheMaxSize: 1, CacheTTL: 1, FailMode: "closed"}, &fakeSafety{})
	for _, tags := range [][]string{
		{"filesystem", "read"},
		{"network", "read"},
		{"exec"},
	} {
		if got := h.failModeFor(tags); got != "closed" {
			t.Fatalf("failModeFor(%v) FailMode=closed = %q, want %q", tags, got, "closed")
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP integration — fail-mode triggers only when gateway unreachable
// ---------------------------------------------------------------------------

func TestFailMode_GatewayReachable_NormalDecision(t *testing.T) {
	// Healthy safety + graduated mode → fail-mode NOT triggered; safety's decision returned.
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "graduated"},
		&fakeSafety{decision: cache.Decision{Decision: "ALLOW", Reason: "ok", Snapshot: "snap-1"}})

	resp := postCheck(t, h, CheckRequest{Tool: "exec", Command: "echo hi"})
	if resp.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW (normal path)", resp.Decision)
	}
	if strings.Contains(resp.Reason, "fail-open") || strings.Contains(resp.Reason, "fail-closed") {
		t.Fatalf("reason = %q, expected normal-path reason (no fail-mode label)", resp.Reason)
	}
}

func TestFailMode_GatewayUnreachable_GraduatedReadAllow(t *testing.T) {
	buf := captureSlog(t)
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "graduated"},
		&fakeSafety{err: errors.New("gateway unreachable")})

	resp := postCheck(t, h, CheckRequest{Tool: "read", Path: "/var/log/app.log"})
	if resp.Decision != "ALLOW" {
		t.Fatalf("decision = %q, want ALLOW (read fail-open)", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "fail-open") {
		t.Fatalf("reason = %q, want substring %q", resp.Reason, "fail-open")
	}
	out := buf.String()
	if !strings.Contains(out, "cordclaw.fail_mode=open") {
		t.Fatalf("slog output missing cordclaw.fail_mode=open: %q", out)
	}
	if !strings.Contains(out, "cordclaw.cordum_reachable=false") {
		t.Fatalf("slog output missing cordclaw.cordum_reachable=false: %q", out)
	}
}

func TestFailMode_GatewayUnreachable_GraduatedExecDeny(t *testing.T) {
	buf := captureSlog(t)
	h := New(config.Config{CacheMaxSize: 100, CacheTTL: 5, FailMode: "graduated"},
		&fakeSafety{err: errors.New("gateway unreachable")})

	resp := postCheck(t, h, CheckRequest{Tool: "exec", Command: "rm -rf /"})
	if resp.Decision != "DENY" {
		t.Fatalf("decision = %q, want DENY (exec fail-closed)", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "fail-closed") {
		t.Fatalf("reason = %q, want substring %q", resp.Reason, "fail-closed")
	}
	out := buf.String()
	if !strings.Contains(out, "cordclaw.fail_mode=closed") {
		t.Fatalf("slog output missing cordclaw.fail_mode=closed: %q", out)
	}
	if !strings.Contains(out, "cordclaw.cordum_reachable=false") {
		t.Fatalf("slog output missing cordclaw.cordum_reachable=false: %q", out)
	}
}
