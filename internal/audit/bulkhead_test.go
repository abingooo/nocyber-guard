package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConcurrencyGateIsSharedAndResizable(t *testing.T) {
	gate := NewConcurrencyGate(1)
	release, err := gate.Acquire(context.Background(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.Acquire(context.Background(), 10*time.Millisecond); !errors.Is(err, ErrAIQueueFull) {
		t.Fatalf("second acquire error = %v, want ErrAIQueueFull", err)
	}

	gate.SetLimit(2)
	releaseSecond, err := gate.Acquire(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("acquire after growing limit: %v", err)
	}
	gate.SetLimit(1)
	if _, err := gate.Acquire(context.Background(), 10*time.Millisecond); !errors.Is(err, ErrAIQueueFull) {
		t.Fatalf("acquire above reduced limit error = %v, want ErrAIQueueFull", err)
	}
	releaseSecond()
	release()
	finalRelease, err := gate.Acquire(context.Background(), time.Second)
	if err != nil {
		t.Fatalf("acquire after releases: %v", err)
	}
	finalRelease()
}
