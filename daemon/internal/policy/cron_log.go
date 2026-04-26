package policy

import (
	"strings"
	"sync"
	"time"
)

const defaultCronDecisionTTL = 24 * time.Hour

// CronDecisionRecord records the policy context that allowed a cron job to be
// created. It intentionally omits cron descriptions/prompts so audit logs and
// in-memory state do not retain sensitive user text.
type CronDecisionRecord struct {
	AllowedAt     time.Time
	AllowedTopics []string
	AllowedTags   []string
	Agent         string
}

type CronDecisionLog struct {
	mu      sync.Mutex
	records map[string]CronDecisionRecord
	ttl     time.Duration
	nowFn   func() time.Time
}

func NewCronDecisionLog(ttl time.Duration) *CronDecisionLog {
	if ttl <= 0 {
		ttl = defaultCronDecisionTTL
	}
	return &CronDecisionLog{
		records: make(map[string]CronDecisionRecord),
		ttl:     ttl,
		nowFn:   time.Now,
	}
}

func (l *CronDecisionLog) SetNowFn(nowFn func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if nowFn == nil {
		l.nowFn = time.Now
		return
	}
	l.nowFn = nowFn
}

// Record stores an ALLOW decision for a cron job. Empty job ids are ignored
// because they cannot safely correlate a future cron-fired turn.
//
// TODO(task-752e64d1): replace the v1 in-memory map with Redis/BoltDB-backed
// persistence so daemon restarts do not evict valid cron approvals.
func (l *CronDecisionLog) Record(jobID string, record CronDecisionRecord) {
	jobID = strings.TrimSpace(jobID)
	if l == nil || jobID == "" {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if record.AllowedAt.IsZero() {
		record.AllowedAt = l.nowFn().UTC()
	}
	record.AllowedTopics = append([]string(nil), record.AllowedTopics...)
	record.AllowedTags = append([]string(nil), record.AllowedTags...)
	l.records[jobID] = record
}

func (l *CronDecisionLog) Lookup(jobID string) (CronDecisionRecord, bool) {
	jobID = strings.TrimSpace(jobID)
	if l == nil || jobID == "" {
		return CronDecisionRecord{}, false
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	record, ok := l.records[jobID]
	if !ok {
		return CronDecisionRecord{}, false
	}
	now := l.nowFn()
	if now.Sub(record.AllowedAt) > l.ttl {
		delete(l.records, jobID)
		return CronDecisionRecord{}, false
	}
	record.AllowedTopics = append([]string(nil), record.AllowedTopics...)
	record.AllowedTags = append([]string(nil), record.AllowedTags...)
	return record, true
}
