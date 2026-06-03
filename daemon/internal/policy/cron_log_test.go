package policy

import (
	"testing"
	"time"
)

func TestCronDecisionLogRecordLookupCopiesData(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	log := NewCronDecisionLog(24 * time.Hour)
	log.SetNowFn(func() time.Time { return now })

	topics := []string{"job.cordclaw.cron-create"}
	tags := []string{"schedule", "autonomy"}
	log.Record("cron-7", CronDecisionRecord{
		AllowedTopics: topics,
		AllowedTags:   tags,
		Agent:         "agent-1",
	})
	topics[0] = "mutated"
	tags[0] = "mutated"

	record, ok := log.Lookup("cron-7")
	if !ok {
		t.Fatalf("expected record")
	}
	if record.AllowedAt != now {
		t.Fatalf("AllowedAt = %v, want %v", record.AllowedAt, now)
	}
	if record.AllowedTopics[0] != "job.cordclaw.cron-create" {
		t.Fatalf("AllowedTopics copied incorrectly: %v", record.AllowedTopics)
	}
	if record.AllowedTags[0] != "schedule" {
		t.Fatalf("AllowedTags copied incorrectly: %v", record.AllowedTags)
	}
	if record.Agent != "agent-1" {
		t.Fatalf("Agent = %q, want agent-1", record.Agent)
	}

	record.AllowedTopics[0] = "mutated-after-lookup"
	record.AllowedTags[0] = "mutated-after-lookup"
	record, ok = log.Lookup("cron-7")
	if !ok {
		t.Fatalf("expected record after mutating returned slices")
	}
	if record.AllowedTopics[0] != "job.cordclaw.cron-create" {
		t.Fatalf("AllowedTopics returned slice alias leaked into store: %v", record.AllowedTopics)
	}
	if record.AllowedTags[0] != "schedule" {
		t.Fatalf("AllowedTags returned slice alias leaked into store: %v", record.AllowedTags)
	}
}

func TestCronDecisionLogLookupEvictsExpiredRecords(t *testing.T) {
	now := time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC)
	log := NewCronDecisionLog(24 * time.Hour)
	log.SetNowFn(func() time.Time { return now })
	log.Record("cron-7", CronDecisionRecord{Agent: "agent-1"})

	log.SetNowFn(func() time.Time { return now.Add(24*time.Hour + time.Nanosecond) })
	if _, ok := log.Lookup("cron-7"); ok {
		t.Fatalf("expected expired cron decision to be evicted")
	}

	log.SetNowFn(func() time.Time { return now })
	if _, ok := log.Lookup("cron-7"); ok {
		t.Fatalf("expected evicted cron decision to stay absent")
	}
}

func TestCronDecisionLogIgnoresEmptyJobID(t *testing.T) {
	log := NewCronDecisionLog(24 * time.Hour)
	log.Record(" ", CronDecisionRecord{Agent: "agent-1"})
	if _, ok := log.Lookup(" "); ok {
		t.Fatalf("expected empty job id not to be stored")
	}
}
