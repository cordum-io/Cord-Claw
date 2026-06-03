package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBoltCronDecisionStoreSurvivesRestart(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cron-decisions.db")

	first := newBoltCronDecisionLogForTest(t, path, 24*time.Hour, now)
	first.Record("cron-7", CronDecisionRecord{
		AllowedTopics:       []string{"job.cordclaw.cron-create"},
		AllowedTags:         []string{"schedule", "autonomy"},
		AllowedTools:        []string{"web_fetch"},
		AllowedCapabilities: []string{"cordclaw.web-fetch"},
		Agent:               "agent-1",
	})
	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	second := newBoltCronDecisionLogForTest(t, path, 24*time.Hour, now.Add(time.Minute))
	defer closeCronDecisionLogForTest(t, second)

	record, ok := second.Lookup("cron-7")
	if !ok {
		t.Fatalf("expected cron decision to survive restart")
	}
	if record.AllowedAt != now {
		t.Fatalf("AllowedAt = %v, want %v", record.AllowedAt, now)
	}
	if got := strings.Join(record.AllowedTopics, ","); got != "job.cordclaw.cron-create" {
		t.Fatalf("AllowedTopics = %q", got)
	}
	if got := strings.Join(record.AllowedTags, ","); got != "schedule,autonomy" {
		t.Fatalf("AllowedTags = %q", got)
	}
	if got := strings.Join(record.AllowedTools, ","); got != "web_fetch" {
		t.Fatalf("AllowedTools = %q", got)
	}
	if got := strings.Join(record.AllowedCapabilities, ","); got != "cordclaw.web-fetch" {
		t.Fatalf("AllowedCapabilities = %q", got)
	}
	if record.Agent != "agent-1" {
		t.Fatalf("Agent = %q, want agent-1", record.Agent)
	}
}

func TestBoltCronDecisionStoreEvictsExpiredRecords(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cron-decisions.db")

	log := newBoltCronDecisionLogForTest(t, path, 24*time.Hour, now)
	log.Record("cron-7", CronDecisionRecord{Agent: "agent-1"})

	log.SetNowFn(func() time.Time { return now.Add(24*time.Hour + time.Nanosecond) })
	if _, ok := log.Lookup("cron-7"); ok {
		t.Fatalf("expected expired cron decision to be evicted")
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close expired store: %v", err)
	}

	reopened := newBoltCronDecisionLogForTest(t, path, 24*time.Hour, now)
	defer closeCronDecisionLogForTest(t, reopened)
	if _, ok := reopened.Lookup("cron-7"); ok {
		t.Fatalf("expected evicted cron decision to stay absent after reopen")
	}
}

func TestBoltCronDecisionStoreIgnoresEmptyJobID(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cron-decisions.db")

	log := newBoltCronDecisionLogForTest(t, path, 24*time.Hour, now)
	defer closeCronDecisionLogForTest(t, log)

	log.Record(" ", CronDecisionRecord{Agent: "agent-1"})
	if _, ok := log.Lookup(" "); ok {
		t.Fatalf("expected empty job id not to be stored")
	}
	if _, ok := log.Lookup(""); ok {
		t.Fatalf("expected blank job id not to be stored")
	}
}

func TestOpenBoltCronDecisionStoreRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cron-decisions.db")
	if err := os.WriteFile(path, []byte("not a bolt database"), 0o600); err != nil {
		t.Fatalf("write corrupt store: %v", err)
	}

	store, err := OpenBoltCronDecisionStore(path)
	if err == nil {
		if store != nil {
			_ = store.Close()
		}
		t.Fatalf("expected corrupt store initialization to fail")
	}
}

func TestBoltCronDecisionStoreDoesNotPersistPromptOrDescriptionText(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "cron-decisions.db")
	secretPrompt := "summarize prod incident sk-test-secret"
	cronDescription := "nightly customer-export prompt"

	log := newBoltCronDecisionLogForTest(t, path, 24*time.Hour, now)
	log.Record("cron-7", CronDecisionRecord{
		AllowedTopics: []string{"job.cordclaw.cron-create"},
		AllowedTags:   []string{"schedule"},
		Agent:         "agent-1",
	})
	if err := log.Close(); err != nil {
		t.Fatalf("close store before disk inspection: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bolt store: %v", err)
	}
	stored := string(raw)
	for _, forbidden := range []string{
		"prompt_text",
		"promptText",
		"prompt",
		"description",
		secretPrompt,
		cronDescription,
	} {
		if strings.Contains(stored, forbidden) {
			t.Fatalf("bolt store leaked forbidden cron prompt/description content %q", forbidden)
		}
	}
}

func newBoltCronDecisionLogForTest(t *testing.T, path string, ttl time.Duration, now time.Time) *CronDecisionLog {
	t.Helper()
	store, err := OpenBoltCronDecisionStore(path)
	if err != nil {
		t.Fatalf("open bolt cron decision store: %v", err)
	}
	log := NewCronDecisionLogWithStore(ttl, store)
	log.SetNowFn(func() time.Time { return now })
	return log
}

func closeCronDecisionLogForTest(t *testing.T, log *CronDecisionLog) {
	t.Helper()
	if err := log.Close(); err != nil {
		t.Fatalf("close cron decision log: %v", err)
	}
}
