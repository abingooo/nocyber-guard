// Package audit contains the protocol-independent security-audit domain used
// by NoCyber Guard.  It deliberately has no dependency on the HTTP proxy or
// on a concrete database so those layers can evolve independently.
package audit

import (
	"context"
	"errors"
	"time"
)

const (
	ProtocolResponses = "openai_responses"

	DefaultMaxBodyBytes       int64         = 4 << 20
	DefaultMaxPromptRunes     int           = 64000
	DefaultJSONDepth          int           = 1024
	DefaultAIConcurrency      int           = 16
	DefaultAIQueueTimeout     time.Duration = 2 * time.Second
	DefaultAITimeout          time.Duration = 15 * time.Second
	DefaultRejectConfidence   float64       = 0.95
	DefaultEventReasonMaxSize               = 128
	DefaultEventClientMaxSize               = 512
)

// Reason is intentionally a stable, machine-readable value.  It is persisted
// in audit_events and displayed by the admin UI.
type Reason string

const (
	ReasonDisabled         Reason = "disabled"
	ReasonRouteBypass      Reason = "route_bypass"
	ReasonProtocolBypass   Reason = "protocol_unreviewed_allow"
	ReasonUABypass         Reason = "ua_bypass"
	ReasonParseBypass      Reason = "parse_bypass"
	ReasonEmptyBypass      Reason = "empty_bypass"
	ReasonOversizeBypass   Reason = "oversize_bypass"
	ReasonRiskHashMatch    Reason = "risk_hash_match"
	ReasonTrustedHashMatch Reason = "trusted_hash_match"
	ReasonAIReject         Reason = "ai_reject"
	ReasonAIPass           Reason = "ai_pass"
	ReasonAIUncertain      Reason = "ai_uncertain"
	ReasonAILowConfidence  Reason = "ai_low_confidence"
	ReasonAIUnavailable    Reason = "ai_unavailable"
	ReasonAIRateLimited    Reason = "ai_rate_limited"
	ReasonAITimeout        Reason = "ai_timeout"
	ReasonAIInvalid        Reason = "ai_invalid"
	ReasonAIBulkhead       Reason = "ai_bulkhead_fail_open"
	ReasonStorageFailOpen  Reason = "storage_fail_open"
	ReasonBodyReadBypass   Reason = "body_read_fail_open"
	ReasonEncodingBypass   Reason = "unsupported_content_encoding_fail_open"
	ReasonDecodeBypass     Reason = "content_decode_fail_open"
	ReasonWebSocketBypass  Reason = "websocket_unreviewed_allow"
)

// FieldState describes what the narrow v0.1 parser found.  Invalid means the
// relevant shape was present but not usable; parsing errors are returned
// separately so callers can distinguish malformed JSON from an empty field.
type FieldState string

const (
	FieldMissing FieldState = "missing"
	FieldEmpty   FieldState = "empty"
	FieldValid   FieldState = "valid"
	FieldInvalid FieldState = "invalid"
)

type Field struct {
	Name      string     `json:"name"`
	State     FieldState `json:"state"`
	Text      string     `json:"-"`
	SHA256    string     `json:"sha256,omitempty"`
	Bytes     int        `json:"bytes,omitempty"`
	Runes     int        `json:"runes,omitempty"`
	AISample  string     `json:"-"`
	AISampled bool       `json:"ai_sampled,omitempty"`
}

func (f Field) IsValid() bool { return f.State == FieldValid && f.Text != "" && f.SHA256 != "" }

type Parsed struct {
	Instructions Field  `json:"instructions"`
	Input1       Field  `json:"input1"`
	Selected     Field  `json:"selected"`
	SelectedName string `json:"selected_name,omitempty"`
	Model        string `json:"model,omitempty"`
}

// Request is the minimum information the audit engine needs from a proxy.
// Body is the original byte sequence; the engine never rewrites it.
type Request struct {
	ID                string
	Method            string
	Path              string
	Protocol          string
	UserAgent         string
	Model             string
	Body              []byte
	APIKeyFingerprint string
	ClientIP          string
}

type Verdict string

const (
	VerdictPass      Verdict = "pass"
	VerdictReject    Verdict = "reject"
	VerdictUncertain Verdict = "uncertain"
)

type AIVerdict struct {
	Result     Verdict `json:"result"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Category   string  `json:"category"`
	Model      string  `json:"model,omitempty"`
	LatencyMS  int64   `json:"latency_ms,omitempty"`
}

type AIReviewRequest struct {
	Field             string
	Content           string
	Sampled           bool
	Model             string
	Criteria          string
	APIKeyFingerprint string
	ClientIP          string
}

type ReviewLimiter interface {
	Allow(time.Time, string, string) bool
}

// Reviewer is injectable so the engine can be tested without a network call.
type Reviewer interface {
	Review(context.Context, AIReviewRequest) (AIVerdict, error)
}

type ReviewerFunc func(context.Context, AIReviewRequest) (AIVerdict, error)

func (f ReviewerFunc) Review(ctx context.Context, req AIReviewRequest) (AIVerdict, error) {
	if f == nil {
		return AIVerdict{}, ErrAIUnavailable
	}
	return f(ctx, req)
}

var (
	ErrInvalidJSON       = errors.New("nocyber guard: invalid JSON")
	ErrJSONDepth         = errors.New("nocyber guard: JSON nesting is too deep")
	ErrDuplicateKey      = errors.New("nocyber guard: duplicate JSON object key")
	ErrNoPrompt          = errors.New("nocyber guard: no supported instruction text")
	ErrBodyTooLarge      = errors.New("nocyber guard: request body exceeds audit limit")
	ErrAIUnavailable     = errors.New("nocyber guard: AI reviewer unavailable")
	ErrAIInvalidResponse = errors.New("nocyber guard: AI response invalid")
	ErrAIQueueFull       = errors.New("nocyber guard: AI concurrency queue full")
)

// HashMatch is returned by a rule store. Risk always wins over trusted when
// both are present; Kind must be either "risk" or "trusted".
type HashMatch struct {
	ID     int64
	SHA256 string
	Kind   string
	Note   string
}

type HashLookup interface {
	LookupHash(context.Context, string) (HashMatch, bool, error)
}

type EventSink interface {
	RecordAuditEvent(context.Context, Event) error
}

// BlockedEventSink persists the decision and its retained plaintext evidence
// in one operation. The engine will not enforce a block unless this operation
// succeeds, preserving the product's fail-open contract.
type BlockedEventSink interface {
	RecordBlockedEvent(context.Context, Event, string, string) error
}

// EventAction describes whether Guard evaluated the request or deliberately
// bypassed an unsupported/disabled request. EventOutcome is the final effect
// on the request. The two fields remain separate so an audited fail-open can
// be distinguished from an intentional protocol bypass.
type EventAction string

const (
	EventActionAudit  EventAction = "audit"
	EventActionBypass EventAction = "bypass"
)

type EventOutcome string

const (
	EventOutcomeAllow    EventOutcome = "allow"
	EventOutcomeBlock    EventOutcome = "block"
	EventOutcomeFailOpen EventOutcome = "fail_open"
)

// Event intentionally excludes plaintext prompt content and API credentials.
type Event struct {
	RequestID    string
	Method       string
	Path         string
	Protocol     string
	Model        string
	UserAgent    string
	ProfileKey   string
	Decision     string
	Action       EventAction
	Outcome      EventOutcome
	Reason       Reason
	Field        string
	SHA256       string
	PromptBytes  int
	PromptRunes  int
	AISampled    bool
	AIVerdict    *AIVerdict
	AuditLatency time.Duration
	AILatency    time.Duration
	// Latency is retained as an internal compatibility alias for events
	// produced by pre-v0.1 callers. New code should set AuditLatency.
	Latency          time.Duration
	UpstreamAccessed bool
	CreatedAt        time.Time
}

// DeriveEventContract fills stable action/outcome values from the reason and
// enforcement decision. It is also used while importing events produced by
// early release candidates that did not populate the new fields.
func DeriveEventContract(reason Reason, blocked bool) (EventAction, EventOutcome) {
	if blocked {
		return EventActionAudit, EventOutcomeBlock
	}
	switch reason {
	case ReasonDisabled, ReasonRouteBypass, ReasonProtocolBypass, ReasonUABypass, ReasonWebSocketBypass:
		return EventActionBypass, EventOutcomeAllow
	case ReasonBodyReadBypass, ReasonEncodingBypass, ReasonDecodeBypass:
		return EventActionBypass, EventOutcomeFailOpen
	case ReasonParseBypass, ReasonEmptyBypass, ReasonOversizeBypass, ReasonAIUncertain, ReasonAILowConfidence,
		ReasonAIUnavailable, ReasonAIRateLimited, ReasonAITimeout, ReasonAIInvalid,
		ReasonAIBulkhead, ReasonStorageFailOpen:
		return EventActionAudit, EventOutcomeFailOpen
	default:
		return EventActionAudit, EventOutcomeAllow
	}
}

type Result struct {
	Allow       bool
	Blocked     bool
	Reason      Reason
	ProfileKey  string
	Field       string
	Hash        string
	PromptBytes int
	PromptRunes int
	AISampled   bool
	// ReviewContent is the bounded sample used by the asynchronous quorum.
	// It is never persisted in ordinary events and is consumed only by the
	// in-process queue after the synchronous decision has completed.
	ReviewContent string
	// RuleContent is the exact selected field used to calculate Hash. It stays
	// out of ordinary events and is used only to persist plaintext alongside a
	// promoted or previously hash-only rule.
	RuleContent  string
	Model        string
	AIVerdict    *AIVerdict
	AuditLatency time.Duration
	AILatency    time.Duration
}

func (r Result) IsFailOpen() bool {
	_, outcome := DeriveEventContract(r.Reason, r.Blocked)
	return r.Allow && outcome == EventOutcomeFailOpen
}
