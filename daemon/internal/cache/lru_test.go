package cache

import (
	"testing"
	"time"
)

func TestLRUSetGetAndExpiry(t *testing.T) {
	l := New(2)
	now := time.Date(2026, time.March, 30, 0, 0, 0, 0, time.UTC)
	l.SetNowFn(func() time.Time { return now })

	l.Set("a", Decision{Decision: "ALLOW"}, time.Minute)
	if _, ok := l.Get("a"); !ok {
		t.Fatalf("expected cache hit")
	}

	now = now.Add(2 * time.Minute)
	if _, ok := l.Get("a"); ok {
		t.Fatalf("expected cache miss after expiry")
	}
}

func TestLRUEvictionPrefersClosestExpiry(t *testing.T) {
	l := New(2)
	now := time.Date(2026, time.March, 30, 0, 0, 0, 0, time.UTC)
	l.SetNowFn(func() time.Time { return now })

	l.Set("slow", Decision{Decision: "ALLOW"}, 10*time.Minute)
	now = now.Add(1 * time.Minute)
	l.Set("soon", Decision{Decision: "DENY"}, 2*time.Minute)
	now = now.Add(1 * time.Minute)
	l.Set("new", Decision{Decision: "ALLOW"}, 10*time.Minute)

	if _, ok := l.Get("soon"); ok {
		t.Fatalf("expected entry with earliest expiry to be evicted")
	}
	if _, ok := l.Get("slow"); !ok {
		t.Fatalf("expected slow entry to stay")
	}
	if _, ok := l.Get("new"); !ok {
		t.Fatalf("expected new entry to stay")
	}
}

func TestKeyForHookIsolatesHookAndAction(t *testing.T) {
	payloadHash := "same-payload-hash"

	webFetchKey := KeyForHook("before_tool_execution", "web_fetch", payloadHash)
	promptKey := KeyForHook("before_prompt_build", "web_fetch", payloadHash)
	execKey := KeyForHook("before_tool_execution", "exec", payloadHash)

	if webFetchKey == promptKey {
		t.Fatalf("same action+payload under different hooks produced same key %q", webFetchKey)
	}
	if webFetchKey == execKey {
		t.Fatalf("same hook+payload under different actions produced same key %q", webFetchKey)
	}
	if webFetchKey != "before_tool_execution:web_fetch:same-payload-hash" {
		t.Fatalf("webFetchKey = %q, want before_tool_execution:web_fetch:same-payload-hash", webFetchKey)
	}
	t.Logf("cache keys: web_fetch=%s prompt=%s exec=%s", webFetchKey, promptKey, execKey)
}
