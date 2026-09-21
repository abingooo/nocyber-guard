package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testRuleStore struct {
	match HashMatch
	found bool
	err   error
}

func (store testRuleStore) LookupHash(context.Context, string) (HashMatch, bool, error) {
	return store.match, store.found, store.err
}

type testEventSink struct {
	events       []Event
	blockedCalls int
	blockedErr   error
}

func (sink *testEventSink) RecordAuditEvent(_ context.Context, event Event) error {
	sink.events = append(sink.events, event)
	return nil
}

func (sink *testEventSink) RecordBlockedEvent(_ context.Context, event Event, _, _ string) error {
	sink.blockedCalls++
	if sink.blockedErr != nil {
		return sink.blockedErr
	}
	sink.events = append(sink.events, event)
	return nil
}

func newTestEngine(t *testing.T, rules HashLookup, reviewer Reviewer, sink EventSink) *Engine {
	t.Helper()
	engine, err := NewEngine(EngineConfig{
		Mode: ModePermissive, Profiles: []ClientProfile{{Key: "known", Name: "Known", Enabled: true, Matchers: []Matcher{{Type: "prefix", Value: "known/"}}}},
		ProtectedPaths: []string{"/v1/responses"}, MaxBodyBytes: 1024 * 1024, MaxPromptRunes: 64,
		RejectConfidenceThreshold: 0.95, AIConcurrency: 1,
	}, rules, reviewer, sink)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func testRequest(body string) Request {
	return Request{ID: "req-1", Method: "POST", Path: "/v1/responses", Protocol: ProtocolResponses, UserAgent: "known/1", Body: []byte(body)}
}

func TestEngineRiskTrustedAndAIOrder(t *testing.T) {
	body := `{"instructions":"danger"}`
	field := newTextField("instructions", "danger")
	trusted := &testEventSink{}
	called := 0
	engine := newTestEngine(t, testRuleStore{match: HashMatch{Kind: "risk", SHA256: field.SHA256}, found: true}, ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
		called++
		return AIVerdict{Result: VerdictPass, Confidence: 1, Reason: "ok", Category: "benign"}, nil
	}), trusted)
	result := engine.Evaluate(context.Background(), testRequest(body))
	if !result.Blocked || result.Reason != ReasonRiskHashMatch || result.RuleContent != "danger" || called != 0 || trusted.blockedCalls != 1 {
		t.Fatalf("risk result=%#v called=%d blockedCalls=%d", result, called, trusted.blockedCalls)
	}

	called = 0
	engine = newTestEngine(t, testRuleStore{match: HashMatch{Kind: "trusted", SHA256: field.SHA256}, found: true}, ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
		called++
		return AIVerdict{Result: VerdictReject, Confidence: 1, Reason: "bad", Category: "risk"}, nil
	}), &testEventSink{})
	result = engine.Evaluate(context.Background(), testRequest(body))
	if !result.Allow || result.Blocked || result.Reason != ReasonTrustedHashMatch || result.RuleContent != "danger" || called != 0 {
		t.Fatalf("trusted result=%#v called=%d", result, called)
	}
}

func TestEngineAIRejectAndFailOpen(t *testing.T) {
	sink := &testEventSink{}
	called := 0
	engine := newTestEngine(t, nil, ReviewerFunc(func(_ context.Context, req AIReviewRequest) (AIVerdict, error) {
		called++
		if req.Content != "danger" {
			t.Errorf("review content = %q", req.Content)
		}
		return AIVerdict{Result: VerdictReject, Confidence: 0.99, Reason: "unsafe", Category: "jailbreak"}, nil
	}), sink)
	result := engine.Evaluate(context.Background(), testRequest(`{"instructions":"danger"}`))
	if !result.Blocked || result.Reason != ReasonAIReject || called != 1 || sink.blockedCalls != 1 {
		t.Fatalf("reject result=%#v called=%d blockedCalls=%d", result, called, sink.blockedCalls)
	}

	engine = newTestEngine(t, nil, ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
		return AIVerdict{}, errors.New("AI down")
	}), &testEventSink{})
	result = engine.Evaluate(context.Background(), testRequest(`{"instructions":"danger"}`))
	if !result.Allow || result.Blocked || result.Reason != ReasonAIUnavailable {
		t.Fatalf("failure result=%#v", result)
	}
}

func TestEngineBlockEvidenceFailureIsFailOpen(t *testing.T) {
	sink := &testEventSink{blockedErr: errors.New("disk full")}
	engine := newTestEngine(t, nil, ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
		return AIVerdict{Result: VerdictReject, Confidence: 1, Reason: "unsafe", Category: "risk"}, nil
	}), sink)
	result := engine.Evaluate(context.Background(), testRequest(`{"instructions":"danger"}`))
	if !result.Allow || result.Blocked || result.Reason != ReasonStorageFailOpen || sink.blockedCalls != 1 {
		t.Fatalf("result=%#v blockedCalls=%d", result, sink.blockedCalls)
	}
}

func TestEngineBypassesUnknownRouteAndOversize(t *testing.T) {
	called := 0
	reviewer := ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
		called++
		return AIVerdict{Result: VerdictReject, Confidence: 1, Reason: "x", Category: "x"}, nil
	})
	engine := newTestEngine(t, nil, reviewer, &testEventSink{})
	request := testRequest(`{"instructions":"x"}`)
	request.UserAgent = "unknown/1"
	result := engine.Evaluate(context.Background(), request)
	if !result.Allow || result.Reason != ReasonUABypass || called != 0 {
		t.Fatalf("unknown UA result=%#v called=%d", result, called)
	}
	request.UserAgent = "known/1"
	request.Path = "/v1/chat/completions"
	result = engine.Evaluate(context.Background(), request)
	if !result.Allow || result.Reason != ReasonRouteBypass || called != 0 {
		t.Fatalf("route result=%#v called=%d", result, called)
	}
}

func TestEngineConfidenceAndInvalidVerdictFailOpen(t *testing.T) {
	for _, verdict := range []AIVerdict{
		{Result: VerdictReject, Confidence: 0.5, Reason: "weak", Category: "risk"},
		{Result: Verdict("maybe"), Confidence: 1, Reason: "bad", Category: "risk"},
	} {
		verdict := verdict
		engine := newTestEngine(t, nil, ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) { return verdict, nil }), &testEventSink{})
		result := engine.Evaluate(context.Background(), testRequest(`{"instructions":"x"}`))
		if !result.Allow || result.Blocked {
			t.Fatalf("verdict %#v result=%#v", verdict, result)
		}
		if verdict.Result == VerdictReject && result.Reason != ReasonAILowConfidence {
			t.Fatalf("low confidence reason=%s", result.Reason)
		}
		if verdict.Result != VerdictReject && result.Reason != ReasonAIInvalid {
			t.Fatalf("invalid reason=%s", result.Reason)
		}
	}
}

func TestDeriveEventContract(t *testing.T) {
	tests := []struct {
		name    string
		reason  Reason
		blocked bool
		action  EventAction
		outcome EventOutcome
	}{
		{"trusted", ReasonTrustedHashMatch, false, EventActionAudit, EventOutcomeAllow},
		{"risk", ReasonRiskHashMatch, true, EventActionAudit, EventOutcomeBlock},
		{"ai reject", ReasonAIReject, true, EventActionAudit, EventOutcomeBlock},
		{"unknown client", ReasonUABypass, false, EventActionBypass, EventOutcomeAllow},
		{"unsupported websocket", ReasonWebSocketBypass, false, EventActionBypass, EventOutcomeAllow},
		{"body read failure", ReasonBodyReadBypass, false, EventActionBypass, EventOutcomeFailOpen},
		{"parse failure", ReasonParseBypass, false, EventActionAudit, EventOutcomeFailOpen},
		{"uncertain reviewer", ReasonAIUncertain, false, EventActionAudit, EventOutcomeFailOpen},
		{"reviewer timeout", ReasonAITimeout, false, EventActionAudit, EventOutcomeFailOpen},
		{"empty supported field", ReasonEmptyBypass, false, EventActionAudit, EventOutcomeFailOpen},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, outcome := DeriveEventContract(tt.reason, tt.blocked)
			if action != tt.action || outcome != tt.outcome {
				t.Fatalf("contract = (%q, %q), want (%q, %q)", action, outcome, tt.action, tt.outcome)
			}
		})
	}
}

func TestEngineRecordsAILatencyOnReviewerFailure(t *testing.T) {
	sink := &testEventSink{}
	now := time.Unix(1700000000, 0)
	engine := newTestEngine(t, nil, ReviewerFunc(func(context.Context, AIReviewRequest) (AIVerdict, error) {
		now = now.Add(37 * time.Millisecond)
		return AIVerdict{}, ErrAIUnavailable
	}), sink)
	engine.now = func() time.Time { return now }

	result := engine.Evaluate(context.Background(), testRequest(`{"instructions":"review me"}`))
	if result.Reason != ReasonAIUnavailable || result.AILatency != 37*time.Millisecond {
		t.Fatalf("result = %#v, want unavailable with 37ms AI latency", result)
	}
	if len(sink.events) != 1 || sink.events[0].AILatency != 37*time.Millisecond || sink.events[0].AuditLatency != 37*time.Millisecond {
		t.Fatalf("events = %#v, want AI and audit latency preserved", sink.events)
	}
	if !sink.events[0].UpstreamAccessed || sink.events[0].Outcome != EventOutcomeFailOpen {
		t.Fatalf("event contract = %#v, want fail-open forwarded event", sink.events[0])
	}
}
