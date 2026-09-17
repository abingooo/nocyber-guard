package audit

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestReviewAsyncFansOutAndQuorumPromotion(t *testing.T) {
	var calls atomic.Int32
	nodes := []AsyncNodeReviewer{
		{Slot: "async_1", Reviewer: ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			calls.Add(1)
			return AIVerdict{Result: VerdictReject, Confidence: .99, Reason: "unsafe", Category: "risk"}, nil
		})},
		{Slot: "async_2", Reviewer: ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			calls.Add(1)
			return AIVerdict{Result: VerdictReject, Confidence: .98, Reason: "unsafe", Category: "risk"}, nil
		})},
		{Slot: "async_3", Reviewer: ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
			calls.Add(1)
			return AIVerdict{Result: VerdictPass, Confidence: .99, Reason: "benign", Category: "template"}, nil
		})},
	}
	votes := ReviewAsync(context.Background(), nodes, AIReviewRequest{Field: "instructions", Content: "x"})
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

func TestQuorumPromotionRequiresAllPassAndIgnoresFailures(t *testing.T) {
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
