package audit

import (
	"context"
	"sync"
	"time"
)

// ConcurrencyGate is shared by all engine generations so a configuration
// reload cannot temporarily multiply the number of in-flight AI reviews.
type ConcurrencyGate struct {
	mu      sync.Mutex
	limit   int
	inUse   int
	changed chan struct{}
}

func NewConcurrencyGate(limit int) *ConcurrencyGate {
	if limit < 1 {
		limit = DefaultAIConcurrency
	}
	return &ConcurrencyGate{limit: limit, changed: make(chan struct{})}
}

func (gate *ConcurrencyGate) SetLimit(limit int) {
	if gate == nil || limit < 1 {
		return
	}
	gate.mu.Lock()
	if gate.limit != limit {
		gate.limit = limit
		gate.notifyLocked()
	}
	gate.mu.Unlock()
}

func (gate *ConcurrencyGate) Acquire(ctx context.Context, wait time.Duration) (func(), error) {
	if gate == nil {
		return func() {}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		gate.mu.Lock()
		if gate.inUse < gate.limit {
			gate.inUse++
			gate.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() {
					gate.mu.Lock()
					if gate.inUse > 0 {
						gate.inUse--
					}
					gate.notifyLocked()
					gate.mu.Unlock()
				})
			}, nil
		}
		changed := gate.changed
		gate.mu.Unlock()

		select {
		case <-changed:
		case <-timer.C:
			return nil, ErrAIQueueFull
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (gate *ConcurrencyGate) notifyLocked() {
	close(gate.changed)
	gate.changed = make(chan struct{})
}
