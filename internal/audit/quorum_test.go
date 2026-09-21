package audit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewAsyncFansOutAndQuorumPromotion(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	reviewer := func(verdict AIVerdict) Reviewer {
		return ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			calls.Add(1)
			started <- struct{}{}
			<-release
			return verdict, nil
		})
	}
	nodes := []AsyncNodeReviewer{
		{Slot: "async_1", Reviewer: reviewer(AIVerdict{Result: VerdictReject, Confidence: .99, Reason: "unsafe", Category: "risk"})},
		{Slot: "async_2", Reviewer: reviewer(AIVerdict{Result: VerdictReject, Confidence: .98, Reason: "unsafe", Category: "risk"})},
		{Slot: "async_3", Reviewer: reviewer(AIVerdict{Result: VerdictPass, Confidence: .99, Reason: "benign", Category: "template"})},
	}
	votesCh := make(chan []AsyncVote, 1)
	go func() {
		votesCh <- ReviewAsync(context.Background(), nodes, AIReviewRequest{Field: "instructions", Content: "x"})
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatalf("only %d reviewers started", calls.Load())
		}
	}
	close(release)
	votes := <-votesCh
	if calls.Load() != 3 || len(votes) < 2 {
		t.Fatalf("calls=%d votes=%d", calls.Load(), len(votes))
	}
	conflict := []AsyncVote{
		{Slot: "async_1", Verdict: AIVerdict{Result: VerdictReject, Confidence: .99}},
		{Slot: "async_2", Verdict: AIVerdict{Result: VerdictReject, Confidence: .98}},
		{Slot: "async_3", Verdict: AIVerdict{Result: VerdictPass, Confidence: .99}},
	}
	if kind, ok := QuorumPromotion(conflict, 3, .95); ok || kind != "" {
		t.Fatalf("promotion=%q ok=%v", kind, ok)
	}
}

func TestQuorumPromotionAllowsTwoMatchingVotesAndIgnoresFailures(t *testing.T) {
	votes := []AsyncVote{
		{Slot: "async_1", Verdict: AIVerdict{Result: VerdictPass, Confidence: .99}},
		{Slot: "async_2", Verdict: AIVerdict{Result: VerdictPass, Confidence: .99}},
		{Slot: "async_3", Err: errors.New("timeout")},
	}
	if kind, ok := QuorumPromotion(votes, 3, .95); !ok || kind != "trusted" {
		t.Fatalf("promotion=%q ok=%v", kind, ok)
	}
	votes = []AsyncVote{
		{Slot: "async_1", Verdict: AIVerdict{Result: VerdictReject, Confidence: .99}},
		{Slot: "async_2", Verdict: AIVerdict{Result: VerdictReject, Confidence: .99}},
		{Slot: "async_3", Err: errors.New("timeout")},
	}
	if kind, ok := QuorumPromotion(votes, 3, .95); !ok || kind != "risk" {
		t.Fatalf("promotion=%q ok=%v", kind, ok)
	}
}

func TestReviewAsyncQuorumDoesNotPromoteConflictingValidVotes(t *testing.T) {
	nodes := []AsyncNodeReviewer{
		{Slot: "async_1", Reviewer: delayedVerdictReviewer(0, VerdictPass)},
		{Slot: "async_2", Reviewer: delayedVerdictReviewer(20*time.Millisecond, VerdictReject)},
		{Slot: "async_3", Reviewer: delayedVerdictReviewer(40*time.Millisecond, VerdictPass)},
	}
	result := ReviewAsyncQuorum(context.Background(), nodes, AIReviewRequest{Field: "instructions", Content: "x"}, .95)
	if !result.Reached || !result.Conflict || result.Kind != "" {
		t.Fatalf("conflicting result promoted: %+v", result)
	}
}

func delayedVerdictReviewer(delay time.Duration, result Verdict) Reviewer {
	return ReviewerFunc(func(ctx context.Context, _ AIReviewRequest) (AIVerdict, error) {
		select {
		case <-time.After(delay):
			return AIVerdict{Result: result, Confidence: .99, Reason: "test", Category: "test"}, nil
		case <-ctx.Done():
			return AIVerdict{}, ctx.Err()
		}
	})
}

func TestReviewAsyncQuorumCancelsSlowThirdNode(t *testing.T) {
	started := make(chan struct{}, 3)
	nodes := []AsyncNodeReviewer{
		{Slot: "async_1", Reviewer: ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			started <- struct{}{}
			return AIVerdict{Result: VerdictPass, Confidence: .99, Reason: "ok", Category: "benign"}, nil
		})},
		{Slot: "async_2", Reviewer: ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			started <- struct{}{}
			return AIVerdict{Result: VerdictPass, Confidence: .99, Reason: "ok", Category: "benign"}, nil
		})},
		{Slot: "async_3", Reviewer: ReviewerFunc(func(ctx context.Context, _ AIReviewRequest) (AIVerdict, error) {
			started <- struct{}{}
			<-ctx.Done()
			return AIVerdict{}, ctx.Err()
		})},
	}
	result := ReviewAsyncQuorum(context.Background(), nodes, AIReviewRequest{Field: "instructions", Content: "x"}, .95)
	if !result.Reached || result.Kind != "trusted" || result.Conflict {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestReviewAsyncQuorumStartsAllNodesConcurrently(t *testing.T) {
	started := make(chan string, 3)
	release := make(chan struct{})
	nodes := make([]AsyncNodeReviewer, 0, 3)
	for i := 1; i <= 3; i++ {
		slot := "async_" + string(rune('0'+i))
		nodes = append(nodes, AsyncNodeReviewer{Slot: slot, Reviewer: ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			started <- slot
			<-release
			return AIVerdict{Result: VerdictPass, Confidence: .99, Reason: "ok", Category: "benign"}, nil
		})})
	}
	resultCh := make(chan QuorumResult, 1)
	go func() {
		resultCh <- ReviewAsyncQuorum(context.Background(), nodes, AIReviewRequest{Field: "instructions", Content: "x"}, .95)
	}()
	seen := map[string]bool{}
	for len(seen) < 3 {
		select {
		case slot := <-started:
			seen[slot] = true
		case <-time.After(time.Second):
			t.Fatalf("only %d reviewers started before release", len(seen))
		}
	}
	close(release)
	result := <-resultCh
	if !result.Reached || result.Kind != "trusted" || result.Conflict {
		t.Fatalf("unexpected concurrent result: %+v", result)
	}
}
