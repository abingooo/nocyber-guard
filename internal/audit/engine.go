package audit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Mode string

const (
	ModePermissive Mode = "permissive"
	ModeOff        Mode = "off"
)

type EngineConfig struct {
	Mode                      Mode
	ProtectedPaths            []string
	Profiles                  []ClientProfile
	MaxBodyBytes              int64
	MaxPromptRunes            int
	RejectConfidenceThreshold float64
	ReviewCriteria            string
	AIConcurrency             int
	AIQueueTimeout            time.Duration
	AITimeout                 time.Duration
	ReviewLimiter             ReviewLimiter
	AIBulkhead                *ConcurrencyGate
}

func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Mode:                      ModePermissive,
		ProtectedPaths:            []string{"/v1/responses"},
		Profiles:                  DefaultClientProfiles(),
		MaxBodyBytes:              DefaultMaxBodyBytes,
		MaxPromptRunes:            DefaultMaxPromptRunes,
		RejectConfidenceThreshold: DefaultRejectConfidence,
		ReviewCriteria:            "Pass only stable, legitimate client instruction templates with a clear benign operational purpose.",
		AIConcurrency:             DefaultAIConcurrency,
		AIQueueTimeout:            DefaultAIQueueTimeout,
		AITimeout:                 DefaultAITimeout,
	}
}

type Engine struct {
	config   EngineConfig
	paths    map[string]struct{}
	profiles *ProfileMatcher
	rules    HashLookup
	reviewer Reviewer
	events   EventSink
	bulkhead *ConcurrencyGate
	now      func() time.Time
}

func NewEngine(config EngineConfig, rules HashLookup, reviewer Reviewer, events EventSink) (*Engine, error) {
	config = normalizeEngineConfig(config)
	if config.Mode != ModePermissive && config.Mode != ModeOff {
		return nil, fmt.Errorf("invalid audit mode %q", config.Mode)
	}
	if config.MaxBodyBytes < 1 || config.MaxPromptRunes < 1 {
		return nil, errors.New("audit body and prompt limits must be positive")
	}
	if config.RejectConfidenceThreshold < 0.5 || config.RejectConfidenceThreshold > 1 {
		return nil, errors.New("reject confidence threshold must be between 0.5 and 1")
	}
	if config.AIConcurrency < 1 || config.AITimeout < 0 || config.AITimeout < time.Millisecond {
		return nil, errors.New("invalid AI concurrency or timeout configuration")
	}
	profiles, err := NewProfileMatcher(config.Profiles)
	if err != nil {
		return nil, err
	}
	paths := make(map[string]struct{}, len(config.ProtectedPaths))
	for _, path := range config.ProtectedPaths {
		path = strings.TrimSpace(path)
		if path == "" || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#") {
			return nil, fmt.Errorf("invalid protected path %q", path)
		}
		paths[path] = struct{}{}
	}
	if len(paths) == 0 {
		return nil, errors.New("at least one protected path is required")
	}
	bulkhead := config.AIBulkhead
	if bulkhead == nil {
		bulkhead = NewConcurrencyGate(config.AIConcurrency)
	}
	return &Engine{
		config: config, paths: paths, profiles: profiles, rules: rules, reviewer: reviewer, events: events,
		bulkhead: bulkhead, now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func normalizeEngineConfig(config EngineConfig) EngineConfig {
	defaults := DefaultEngineConfig()
	if config.Mode == "" {
		config.Mode = defaults.Mode
	}
	if len(config.ProtectedPaths) == 0 {
		config.ProtectedPaths = defaults.ProtectedPaths
	}
	if config.Profiles == nil {
		config.Profiles = defaults.Profiles
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = defaults.MaxBodyBytes
	}
	if config.MaxPromptRunes == 0 {
		config.MaxPromptRunes = defaults.MaxPromptRunes
	}
	if config.RejectConfidenceThreshold == 0 {
		config.RejectConfidenceThreshold = defaults.RejectConfidenceThreshold
	}
	if strings.TrimSpace(config.ReviewCriteria) == "" {
		config.ReviewCriteria = defaults.ReviewCriteria
	}
	if config.AIConcurrency == 0 {
		config.AIConcurrency = defaults.AIConcurrency
	}
	if config.AIQueueTimeout == 0 {
		config.AIQueueTimeout = defaults.AIQueueTimeout
	}
	if config.AITimeout == 0 {
		config.AITimeout = defaults.AITimeout
	}
	return config
}

// Evaluate never returns an operational error. Every parser, storage and AI
// failure is converted into an explicit allow result so callers cannot
// accidentally turn permissive mode into fail-closed behavior.
func (engine *Engine) Evaluate(ctx context.Context, request Request) Result {
	started := engine.now()
	if ctx == nil {
		ctx = context.Background()
	}
	if engine.config.Mode == ModeOff {
		return engine.finish(ctx, request, Result{Allow: true, Reason: ReasonDisabled}, started, false)
	}
	if request.Method == "" {
		request.Method = http.MethodPost
	}
	if request.Protocol != "" && request.Protocol != ProtocolResponses {
		return engine.finish(ctx, request, Result{Allow: true, Reason: ReasonRouteBypass}, started, false)
	}
	if strings.ToUpper(request.Method) != http.MethodPost || !engine.protected(request.Path) {
		return engine.finish(ctx, request, Result{Allow: true, Reason: ReasonRouteBypass}, started, false)
	}
	if int64(len(request.Body)) > engine.config.MaxBodyBytes {
		return engine.finish(ctx, request, Result{Allow: true, Reason: ReasonOversizeBypass}, started, true)
	}
	profile, matched := engine.profiles.Match(request.UserAgent)
	if !matched {
		return engine.finish(ctx, request, Result{Allow: true, Reason: ReasonUABypass}, started, true)
	}

	parsed, err := ParseResponses(ctx, request.Body, DefaultJSONDepth)
	if err != nil {
		return engine.finish(ctx, request, Result{Allow: true, Reason: ReasonParseBypass, ProfileKey: profile.Key}, started, true)
	}
	request.Model = parsed.Model
	fieldName, field := SelectField(parsed)
	if fieldName == "" {
		reason := ReasonEmptyBypass
		if parsed.Instructions.State == FieldInvalid || parsed.Input1.State == FieldInvalid {
			reason = ReasonParseBypass
		}
		return engine.finish(ctx, request, Result{Allow: true, Reason: reason, ProfileKey: profile.Key}, started, true)
	}
	field = PrepareAISample(field, engine.config.MaxPromptRunes)
	base := Result{
		Allow: true, ProfileKey: profile.Key, Field: fieldName, Hash: field.SHA256,
		PromptBytes: field.Bytes, PromptRunes: field.Runes, AISampled: field.AISampled, Model: request.Model,
	}

	if engine.rules != nil {
		match, found, lookupErr := engine.rules.LookupHash(ctx, field.SHA256)
		if lookupErr != nil {
			base.Reason = ReasonStorageFailOpen
			return engine.finish(ctx, request, base, started, true)
		}
		if found {
			switch strings.ToLower(strings.TrimSpace(match.Kind)) {
			case "risk":
				base.Allow, base.Blocked, base.Reason = false, true, ReasonRiskHashMatch
				return engine.finishBlock(ctx, request, base, field.Text, started)
			case "trusted":
				base.Reason = ReasonTrustedHashMatch
				return engine.finish(ctx, request, base, started, true)
			default:
				base.Reason = ReasonStorageFailOpen
				return engine.finish(ctx, request, base, started, true)
			}
		}
	}

	if engine.reviewer == nil {
		base.Reason = ReasonAIUnavailable
		return engine.finish(ctx, request, base, started, true)
	}
	if engine.config.ReviewLimiter != nil && !engine.config.ReviewLimiter.Allow(engine.now(), request.APIKeyFingerprint, request.ClientIP) {
		base.Reason = ReasonAIRateLimited
		return engine.finish(ctx, request, base, started, true)
	}
	release, err := engine.acquire(ctx)
	if err != nil {
		base.Reason = ReasonAIBulkhead
		if errors.Is(err, context.DeadlineExceeded) {
			base.Reason = ReasonAITimeout
		}
		return engine.finish(ctx, request, base, started, true)
	}
	defer release()

	reviewCtx, cancel := context.WithTimeout(ctx, engine.config.AITimeout)
	reviewStarted := engine.now()
	verdict, reviewErr := engine.reviewer.Review(reviewCtx, AIReviewRequest{
		Field: fieldName, Content: field.AISample, Sampled: field.AISampled,
		Model: request.Model, Criteria: engine.config.ReviewCriteria,
		APIKeyFingerprint: request.APIKeyFingerprint, ClientIP: request.ClientIP,
	})
	cancel()
	base.AILatency = engine.now().Sub(reviewStarted)
	verdict.LatencyMS = base.AILatency.Milliseconds()
	if reviewErr != nil {
		switch {
		case errors.Is(reviewErr, context.DeadlineExceeded), errors.Is(reviewCtx.Err(), context.DeadlineExceeded):
			base.Reason = ReasonAITimeout
		case errors.Is(reviewErr, ErrAIInvalidResponse):
			base.Reason = ReasonAIInvalid
		default:
			base.Reason = ReasonAIUnavailable
		}
		return engine.finish(ctx, request, base, started, true)
	}
	if err := ValidateAIVerdict(verdict); err != nil {
		base.Reason = ReasonAIInvalid
		return engine.finish(ctx, request, base, started, true)
	}
	base.AIVerdict = &verdict
	switch verdict.Result {
	case VerdictReject:
		if verdict.Confidence < engine.config.RejectConfidenceThreshold {
			base.Reason = ReasonAILowConfidence
			return engine.finish(ctx, request, base, started, true)
		}
		base.Allow, base.Blocked, base.Reason = false, true, ReasonAIReject
	case VerdictPass:
		base.Reason = ReasonAIPass
	case VerdictUncertain:
		base.Reason = ReasonAIUncertain
	}
	if base.Blocked {
		return engine.finishBlock(ctx, request, base, field.Text, started)
	}
	return engine.finish(ctx, request, base, started, true)
}

func ValidateAIVerdict(verdict AIVerdict) error {
	if verdict.Result != VerdictPass && verdict.Result != VerdictReject && verdict.Result != VerdictUncertain {
		return ErrAIInvalidResponse
	}
	if verdict.Confidence < 0 || verdict.Confidence > 1 || strings.TrimSpace(verdict.Reason) == "" ||
		len(verdict.Reason) > 1000 || strings.TrimSpace(verdict.Category) == "" || len(verdict.Category) > 120 {
		return ErrAIInvalidResponse
	}
	return nil
}

func (engine *Engine) protected(path string) bool {
	_, ok := engine.paths[path]
	return ok
}

func (engine *Engine) acquire(ctx context.Context) (func(), error) {
	return engine.bulkhead.Acquire(ctx, engine.config.AIQueueTimeout)
}

func (engine *Engine) finish(ctx context.Context, request Request, result Result, started time.Time, record bool) Result {
	result.AuditLatency = engine.now().Sub(started)
	if !record || engine.events == nil {
		return result
	}
	event := engine.event(request, result)
	_ = engine.events.RecordAuditEvent(ctx, event)
	return result
}

func (engine *Engine) finishBlock(ctx context.Context, request Request, result Result, plaintext string, started time.Time) Result {
	result.AuditLatency = engine.now().Sub(started)
	recorder, ok := engine.events.(BlockedEventSink)
	if !ok {
		result.Allow, result.Blocked, result.Reason = true, false, ReasonStorageFailOpen
		return engine.finish(ctx, request, result, started, true)
	}
	event := engine.event(request, result)
	if err := recorder.RecordBlockedEvent(ctx, event, result.Field, plaintext); err != nil {
		result.Allow, result.Blocked, result.Reason = true, false, ReasonStorageFailOpen
		return engine.finish(ctx, request, result, started, true)
	}
	return result
}

func (engine *Engine) event(request Request, result Result) Event {
	decision := "allow"
	if result.Blocked {
		decision = "block"
	}
	action, outcome := DeriveEventContract(result.Reason, result.Blocked)
	var verdict *AIVerdict
	aiLatency := result.AILatency
	if result.AIVerdict != nil {
		copy := *result.AIVerdict
		verdict = &copy
		if aiLatency == 0 {
			aiLatency = time.Duration(copy.LatencyMS) * time.Millisecond
		}
	}
	return Event{
		RequestID: request.ID, Method: request.Method, Path: request.Path, Protocol: request.Protocol,
		Model: result.Model, UserAgent: SanitizeUserAgent(request.UserAgent), ProfileKey: result.ProfileKey,
		Decision: decision, Action: action, Outcome: outcome, Reason: result.Reason, Field: result.Field, SHA256: result.Hash,
		PromptBytes: result.PromptBytes, PromptRunes: result.PromptRunes, AISampled: result.AISampled,
		AIVerdict: verdict, AuditLatency: result.AuditLatency, AILatency: aiLatency,
		UpstreamAccessed: !result.Blocked, CreatedAt: engine.now(),
	}
}
