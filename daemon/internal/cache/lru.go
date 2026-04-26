package cache

import (
	"strings"
	"sync"
	"time"
)

type Decision struct {
	Decision    string         `json:"decision"`
	Reason      string         `json:"reason"`
	Constraints map[string]any `json:"constraints,omitempty"`
	ApprovalRef string         `json:"approvalRef,omitempty"`
	Snapshot    string         `json:"snapshot,omitempty"`
}

type entry struct {
	value      Decision
	expiresAt  time.Time
	lastAccess time.Time
}

type LRU struct {
	mu      sync.Mutex
	items   map[string]entry
	maxSize int
	nowFn   func() time.Time
}

func New(maxSize int) *LRU {
	if maxSize <= 0 {
		maxSize = 1
	}
	return &LRU{
		items:   make(map[string]entry, maxSize),
		maxSize: maxSize,
		nowFn:   time.Now,
	}
}

func KeyForHook(hook, action, payloadHash string) string {
	hook = strings.TrimSpace(hook)
	if hook == "" {
		hook = "before_tool_execution"
	}
	action = strings.TrimSpace(action)
	if action == "" {
		action = "unknown"
	}
	return hook + ":" + action + ":" + strings.TrimSpace(payloadHash)
}

func (l *LRU) SetNowFn(nowFn func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if nowFn == nil {
		l.nowFn = time.Now
		return
	}
	l.nowFn = nowFn
}

func (l *LRU) Get(key string) (Decision, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFn()
	ent, ok := l.items[key]
	if !ok {
		return Decision{}, false
	}
	if now.After(ent.expiresAt) {
		delete(l.items, key)
		return Decision{}, false
	}
	ent.lastAccess = now
	l.items[key] = ent
	return ent.value, true
}

func (l *LRU) Set(key string, value Decision, ttl time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.nowFn()
	l.items[key] = entry{
		value:      value,
		expiresAt:  now.Add(ttl),
		lastAccess: now,
	}

	l.sweepExpiredLocked(now)
	for len(l.items) > l.maxSize {
		l.evictOneLocked()
	}
}

func (l *LRU) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepExpiredLocked(l.nowFn())
	return len(l.items)
}

func (l *LRU) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = make(map[string]entry, l.maxSize)
}

func (l *LRU) sweepExpiredLocked(now time.Time) {
	for key, ent := range l.items {
		if now.After(ent.expiresAt) {
			delete(l.items, key)
		}
	}
}

func (l *LRU) evictOneLocked() {
	var victimKey string
	var victim entry
	first := true
	for key, ent := range l.items {
		if first {
			victimKey = key
			victim = ent
			first = false
			continue
		}
		if ent.expiresAt.Before(victim.expiresAt) {
			victimKey = key
			victim = ent
			continue
		}
		if ent.expiresAt.Equal(victim.expiresAt) && ent.lastAccess.Before(victim.lastAccess) {
			victimKey = key
			victim = ent
		}
	}
	if !first {
		delete(l.items, victimKey)
	}
}
