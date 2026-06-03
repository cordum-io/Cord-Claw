package policy

import (
	"fmt"
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

type CronDecisionStore interface {
	Put(jobID string, record CronDecisionRecord) error
	Get(jobID string) (CronDecisionRecord, bool, error)
	Delete(jobID string) error
	Close() error
}

type CronDecisionLog struct {
	mu    sync.RWMutex
	store CronDecisionStore
	ttl   time.Duration
	nowFn func() time.Time
}

func NewCronDecisionLog(ttl time.Duration) *CronDecisionLog {
	return NewCronDecisionLogWithStore(ttl, NewMemoryCronDecisionStore())
}

func NewCronDecisionLogWithStore(ttl time.Duration, store CronDecisionStore) *CronDecisionLog {
	if ttl <= 0 {
		ttl = defaultCronDecisionTTL
	}
	if store == nil {
		store = NewMemoryCronDecisionStore()
	}
	return &CronDecisionLog{
		store: store,
		ttl:   ttl,
		nowFn: time.Now,
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

func (l *CronDecisionLog) Record(jobID string, record CronDecisionRecord) {
	_ = l.RecordWithError(jobID, record)
}

// RecordWithError stores an ALLOW decision for a cron job. Empty job ids are
// ignored because they cannot safely correlate a future cron-fired turn.
func (l *CronDecisionLog) RecordWithError(jobID string, record CronDecisionRecord) error {
	jobID = strings.TrimSpace(jobID)
	if l == nil || jobID == "" {
		return nil
	}

	now := l.now()
	if record.AllowedAt.IsZero() {
		record.AllowedAt = now.UTC()
	}
	if err := l.store.Put(jobID, copyCronDecisionRecord(record)); err != nil {
		return fmt.Errorf("cron decision log record: %w", err)
	}
	return nil
}

func (l *CronDecisionLog) Lookup(jobID string) (CronDecisionRecord, bool) {
	record, ok, _ := l.LookupWithError(jobID)
	return record, ok
}

func (l *CronDecisionLog) LookupWithError(jobID string) (CronDecisionRecord, bool, error) {
	jobID = strings.TrimSpace(jobID)
	if l == nil || jobID == "" {
		return CronDecisionRecord{}, false, nil
	}

	record, ok, err := l.store.Get(jobID)
	if err != nil {
		return CronDecisionRecord{}, false, fmt.Errorf("cron decision log lookup: %w", err)
	}
	if !ok {
		return CronDecisionRecord{}, false, nil
	}
	if l.now().Sub(record.AllowedAt) > l.ttl {
		if err := l.store.Delete(jobID); err != nil {
			return CronDecisionRecord{}, false, fmt.Errorf("cron decision log evict: %w", err)
		}
		return CronDecisionRecord{}, false, nil
	}
	return copyCronDecisionRecord(record), true, nil
}

func (l *CronDecisionLog) Close() error {
	if l == nil || l.store == nil {
		return nil
	}
	return l.store.Close()
}

func (l *CronDecisionLog) now() time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.nowFn()
}

func copyCronDecisionRecord(record CronDecisionRecord) CronDecisionRecord {
	record.AllowedTopics = append([]string(nil), record.AllowedTopics...)
	record.AllowedTags = append([]string(nil), record.AllowedTags...)
	return record
}
