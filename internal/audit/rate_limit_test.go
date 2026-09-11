package audit

import (
	"testing"
	"time"
)

func TestFixedWindowLimiterUsesBothFingerprintAndIP(t *testing.T) {
	now := time.Unix(100, 0)
	limiter := NewFixedWindowLimiter(2, time.Minute)
	if !limiter.Allow(now, "key-a", "10.0.0.1") || !limiter.Allow(now, "key-a", "10.0.0.1") {
		t.Fatal("initial calls rejected")
	}
	if limiter.Allow(now, "key-a", "10.0.0.2") {
		t.Fatal("fingerprint limit bypassed by changing IP")
	}
	if limiter.Allow(now, "key-b", "10.0.0.1") {
		t.Fatal("IP limit bypassed by changing key")
	}
	if !limiter.Allow(now.Add(time.Minute), "key-a", "10.0.0.1") {
		t.Fatal("window did not reset")
	}
}
