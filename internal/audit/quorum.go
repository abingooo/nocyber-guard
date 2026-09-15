package audit

import (
	"context"
	"sync"
	"time"
)

// AsyncNodeReviewer identifies one independent reviewer in the v0.2 quorum.
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

// ReviewAsync fans out to all configured nodes concurrently. The caller owns
// persistence of the returned votes and may safely treat missing/failed nodes
// as non-votes.
func ReviewAsync(ctx context.Context, nodes []AsyncNodeReviewer, request AIReviewRequest) []AsyncVote {
	if ctx == nil {
		ctx = context.Background()
	}
	votes := make([]AsyncVote, len(nodes))
	var wg sync.WaitGroup
	for i, node := range nodes {
		votes[i].Slot = node.Slot
		wg.Add(1)
		go func(i int, node AsyncNodeReviewer) {
			defer wg.Done()
			started := time.Now()
			if node.Reviewer == nil {
				votes[i].Err = ErrAIUnavailable
				return
			}
			verdict, err := node.Reviewer.Review(ctx, request)
			votes[i].Latency = time.Since(started)
			if err == nil {
				err = ValidateAIVerdict(verdict)
			}
			votes[i].Verdict = verdict
			votes[i].Err = err
		}(i, node)
	}
	wg.Wait()
	return votes
}

// QuorumPromotion applies the deliberately asymmetric policy used by v0.2:
// two high-confidence rejects create a risk rule, while trust requires every
// configured node to return a high-confidence pass. Disagreement, uncertain
// results and an incomplete pass vote produce no promotion.
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
	if rejects >= 2 && configured >= 3 {
		return "risk", true
	}
	if passes == configured && configured == 3 {
		return "trusted", true
	}
	return "", false
}
