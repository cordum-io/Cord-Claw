package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

var cronDecisionBucket = []byte("cron_decisions_v1")

type BoltCronDecisionStore struct {
	db        *bolt.DB
	closeOnce sync.Once
	closeErr  error
}

func OpenBoltCronDecisionStore(path string) (*BoltCronDecisionStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("cron decision bolt store path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create cron decision store directory: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open cron decision bolt store: %w", err)
	}
	store := &BoltCronDecisionStore{db: db}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(cronDecisionBucket)
		return err
	}); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("initialize cron decision bolt store: %w", err)
	}
	return store, nil
}

func (s *BoltCronDecisionStore) Put(jobID string, record CronDecisionRecord) error {
	jobID = strings.TrimSpace(jobID)
	if s == nil || s.db == nil || jobID == "" {
		return nil
	}

	encoded, err := json.Marshal(copyCronDecisionRecord(record))
	if err != nil {
		return fmt.Errorf("marshal cron decision record: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(cronDecisionBucket)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(jobID), encoded)
	})
}

func (s *BoltCronDecisionStore) Get(jobID string) (CronDecisionRecord, bool, error) {
	jobID = strings.TrimSpace(jobID)
	if s == nil || s.db == nil || jobID == "" {
		return CronDecisionRecord{}, false, nil
	}

	var record CronDecisionRecord
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(cronDecisionBucket)
		if bucket == nil {
			return nil
		}
		value := bucket.Get([]byte(jobID))
		if value == nil {
			return nil
		}
		found = true
		return json.Unmarshal(value, &record)
	})
	if err != nil {
		return CronDecisionRecord{}, false, err
	}
	if !found {
		return CronDecisionRecord{}, false, nil
	}
	return copyCronDecisionRecord(record), true, nil
}

func (s *BoltCronDecisionStore) Delete(jobID string) error {
	jobID = strings.TrimSpace(jobID)
	if s == nil || s.db == nil || jobID == "" {
		return nil
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(cronDecisionBucket)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(jobID))
	})
}

func (s *BoltCronDecisionStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}
