package policy

import (
	"strings"
	"sync"
)

type MemoryCronDecisionStore struct {
	mu      sync.Mutex
	records map[string]CronDecisionRecord
}

func NewMemoryCronDecisionStore() *MemoryCronDecisionStore {
	return &MemoryCronDecisionStore{records: make(map[string]CronDecisionRecord)}
}

func (s *MemoryCronDecisionStore) Put(jobID string, record CronDecisionRecord) error {
	jobID = strings.TrimSpace(jobID)
	if s == nil || jobID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[jobID] = copyCronDecisionRecord(record)
	return nil
}

func (s *MemoryCronDecisionStore) Get(jobID string) (CronDecisionRecord, bool, error) {
	jobID = strings.TrimSpace(jobID)
	if s == nil || jobID == "" {
		return CronDecisionRecord{}, false, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[jobID]
	if !ok {
		return CronDecisionRecord{}, false, nil
	}
	return copyCronDecisionRecord(record), true, nil
}

func (s *MemoryCronDecisionStore) Delete(jobID string) error {
	jobID = strings.TrimSpace(jobID)
	if s == nil || jobID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, jobID)
	return nil
}

func (s *MemoryCronDecisionStore) Close() error {
	return nil
}
