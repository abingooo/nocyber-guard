package audit

import (
	"sync"
	"time"
)

const maxRateLimitBuckets = 8192

// FixedWindowLimiter limits reviewer calls by credential fingerprint and IP.
// It never receives or retains the raw Authorization value.
type FixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	buckets map[string]rateBucket
}
type rateBucket struct {
	started time.Time
	count   int
}

func NewFixedWindowLimiter(limit int, window time.Duration) *FixedWindowLimiter {
	if limit < 1 {
		limit = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	return &FixedWindowLimiter{limit: limit, window: window, buckets: make(map[string]rateBucket)}
}

func (l *FixedWindowLimiter) Allow(now time.Time, fingerprint, ip string) bool {
	if l == nil {
		return true
	}
	keys := make([]string, 0, 2)
	if fingerprint != "" {
		keys = append(keys, "key:"+fingerprint)
	}
	if ip != "" {
		keys = append(keys, "ip:"+ip)
	}
	if len(keys) == 0 {
		keys = append(keys, "anonymous")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets)+len(keys) > maxRateLimitBuckets {
		for key, bucket := range l.buckets {
			if now.Sub(bucket.started) >= l.window {
				delete(l.buckets, key)
			}
		}
	}
	missing := 0
	for _, key := range keys {
		if _, found := l.buckets[key]; !found {
			missing++
		}
	}
	if len(l.buckets)+missing > maxRateLimitBuckets {
		// Capacity pressure skips AI review and therefore preserves fail-open
		// behavior without allowing arbitrary credentials to grow memory.
		return false
	}
	for _, key := range keys {
		bucket := l.buckets[key]
		if bucket.started.IsZero() || now.Sub(bucket.started) >= l.window {
			bucket = rateBucket{started: now}
		}
		if bucket.count >= l.limit {
			return false
		}
	}
	for _, key := range keys {
		bucket := l.buckets[key]
		if bucket.started.IsZero() || now.Sub(bucket.started) >= l.window {
			bucket = rateBucket{started: now}
		}
		bucket.count++
		l.buckets[key] = bucket
	}
	return true
}
