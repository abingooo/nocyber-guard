package audit

import (
	"context"
	"sync"
	"time"
)

// AsyncNodeReviewer identifies one independent reviewer in the v0.3 quorum.
// A failed node is returned as an error and never counts towards either side
// of the vote.
type AsyncNodeReviewer struct {
	Slot     string
	Reviewer Reviewer
}

type AsyncVote struct {
	Slot    string
	Verdict AIVerdict
	Err     error
	Latency time.Duration
}

type QuorumResult struct {
	Votes    []AsyncVote
	Kind     string
	Reached  bool
	Conflict bool
}

// ReviewAsync fans out to all configured nodes concurrently. The caller owns
// persistence of the returned votes and may safely treat missing/failed nodes
// as non-votes.
func ReviewAsync(ctx context.Context, nodes []AsyncNodeReviewer, request AIReviewRequest) []AsyncVote {
	return ReviewAsyncQuorum(ctx, nodes, request, DefaultRejectConfidence).Votes
}

// ReviewAsyncQuorum starts every configured reviewer at once. A quorum is
// accepted as soon as two same-kind high-confidence votes arrive; outstanding
// calls are cancelled and treated as non-votes. A valid opposite vote already
// received before the quorum wins makes the result a conflict instead.
func ReviewAsyncQuorum(ctx context.Context, nodes []AsyncNodeReviewer, request AIReviewRequest, threshold float64) QuorumResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if threshold <= 0 {
		threshold = DefaultRejectConfidence
	}
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	votesCh := make(chan AsyncVote, len(nodes))
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(node AsyncNodeReviewer) {
			defer wg.Done()
			started := time.Now()
			vote := AsyncVote{Slot: node.Slot}
			if node.Reviewer == nil {
				vote.Err = ErrAIUnavailable
				votesCh <- vote
				return
			}
			verdict, err := node.Reviewer.Review(callCtx, request)
			vote.Latency = time.Since(started)
			if err == nil {
				err = ValidateAIVerdict(verdict)
			}
			vote.Verdict = verdict
			vote.Err = err
			votesCh <- vote
		}(node)
	}
	result := QuorumResult{Votes: make([]AsyncVote, 0, len(nodes))}
	passes, rejects := 0, 0
	remaining := len(nodes)
	for remaining > 0 {
		vote := <-votesCh
		result.Votes = append(result.Votes, vote)
		remaining--
		if vote.Err == nil && vote.Verdict.Confidence >= threshold {
			switch vote.Verdict.Result {
			case VerdictPass:
				passes++
			case VerdictReject:
				rejects++
			}
		}
		if passes >= 2 || rejects >= 2 {
			// Consume results that were already produced before deciding, so a
			// simultaneous opposite valid vote is treated as a conflict.
			draining := true
			for draining {
				select {
				case extra := <-votesCh:
					result.Votes = append(result.Votes, extra)
					remaining--
					if extra.Err == nil && extra.Verdict.Confidence >= threshold {
						if extra.Verdict.Result == VerdictPass {
							passes++
						} else if extra.Verdict.Result == VerdictReject {
							rejects++
						}
					}
				default:
					draining = false
				}
			}
			result.Reached = true
			result.Conflict = passes > 0 && rejects > 0
			if !result.Conflict {
				if passes >= 2 {
					result.Kind = "trusted"
				} else {
					result.Kind = "risk"
				}
			}
			cancel()
			break
		}
	}
	if !result.Reached {
		result.Kind, result.Reached = QuorumPromotion(result.Votes, len(nodes), threshold)
		result.Conflict = passes > 0 && rejects > 0
	}
	// Reviewers are expected to honor cancellation. They only write to the
	// buffered channel, so no goroutine is left blocked if a provider is slow.
	go func() { wg.Wait() }()
	return result
}

// QuorumPromotion applies the v0.3 symmetric policy: two high-confidence
// same-kind votes are enough when the remaining node is absent or invalid.
// Opposite valid votes are a conflict and produce no promotion.
func QuorumPromotion(votes []AsyncVote, configured int, threshold float64) (string, bool) {
	if configured <= 0 || len(votes) == 0 {
		return "", false
	}
	if threshold <= 0 {
		threshold = DefaultRejectConfidence
	}
	rejects, passes := 0, 0
	for _, vote := range votes {
		if vote.Err != nil || vote.Verdict.Confidence < threshold {
			continue
		}
		switch vote.Verdict.Result {
		case VerdictReject:
			rejects++
		case VerdictPass:
			passes++
		}
	}
	if rejects >= 2 && passes == 0 && configured >= 3 {
		return "risk", true
	}
	if passes >= 2 && rejects == 0 && configured >= 3 {
		return "trusted", true
	}
	return "", false
}
