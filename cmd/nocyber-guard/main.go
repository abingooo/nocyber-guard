package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/abingooo/nocyber-guard/internal/admin"
	"github.com/abingooo/nocyber-guard/internal/audit"
	"github.com/abingooo/nocyber-guard/internal/config"
	"github.com/abingooo/nocyber-guard/internal/proxy"
	"github.com/abingooo/nocyber-guard/internal/storage"
)

type runtime struct {
	state          atomic.Value
	store          *storage.Store
	cfg            atomic.Value
	limiter        *audit.FixedWindowLimiter
	fingerprintKey []byte
	trustedProxies []*net.IPNet
	events         chan audit.Event
	eventDrops     atomic.Uint64
	eventWarningAt atomic.Int64
	worker         sync.WaitGroup
	logger         *slog.Logger
	reloadMu       sync.Mutex
	bulkhead       *audit.ConcurrencyGate
	asyncRunner    *asyncRuntime
}

type runtimeState struct {
	engine              *audit.Engine
	paths               map[string]struct{}
	rules               ruleSnapshot
	adminFrameAncestors []string
	auditBodyLimit      int64
	enabled             bool
}

type ruleSnapshot map[string]audit.HashMatch

func (rules ruleSnapshot) LookupHash(_ context.Context, sha string) (audit.HashMatch, bool, error) {
	match, found := rules[sha]
	return match, found, nil
}

type asyncReviewJob struct {
	Hash              string
	Field             string
	Content           string
	RuleContent       string
	Sampled           bool
	Model             string
	APIKeyFingerprint string
	APIKeyHint        string
}

type asyncRuntime struct {
	store       *storage.Store
	logger      *slog.Logger
	queue       chan asyncReviewJob
	mu          sync.RWMutex
	nodes       []audit.AsyncNodeReviewer
	stop        chan struct{}
	done        chan struct{}
	onPromotion func(context.Context) error
}

func newAsyncRuntime(store *storage.Store, logger *slog.Logger) *asyncRuntime {
	return &asyncRuntime{store: store, logger: logger, queue: make(chan asyncReviewJob, 256), stop: make(chan struct{}), done: make(chan struct{})}
}

func (ar *asyncRuntime) setNodes(nodes []audit.AsyncNodeReviewer) {
	ar.mu.Lock()
	ar.nodes = append([]audit.AsyncNodeReviewer(nil), nodes...)
	ar.mu.Unlock()
}

func (ar *asyncRuntime) snapshotNodes() []audit.AsyncNodeReviewer {
	ar.mu.RLock()
	defer ar.mu.RUnlock()
	return append([]audit.AsyncNodeReviewer(nil), ar.nodes...)
}

func (ar *asyncRuntime) enqueue(job asyncReviewJob) bool {
	select {
	case ar.queue <- job:
		return true
	default:
		ar.logger.Warn("async_review_queue_full", "sha256", job.Hash)
		return false
	}
}

func (ar *asyncRuntime) start() {
	go func() {
		defer close(ar.done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		ar.recoverDue()
		for {
			select {
			case <-ar.stop:
				return
			case job := <-ar.queue:
				ar.process(job)
			case <-ticker.C:
				ar.recoverDue()
			}
		}
	}()
}

func (ar *asyncRuntime) recoverDue() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := ar.store.RequeueStaleReviewJobs(ctx, 2*time.Minute); err != nil {
		ar.logger.Warn("async_review_requeue_failed", "error", err)
	}
	jobs, err := ar.store.ListDueReviewJobs(ctx, 25)
	if err != nil {
		ar.logger.Warn("async_review_recovery_failed", "error", err)
		return
	}
	for _, record := range jobs {
		sample, err := ar.store.LoadReviewJobSample(ctx, record.ID)
		if err != nil || sample == "" {
			continue
		}
		ruleContent, contentErr := ar.store.LoadReviewJobContent(ctx, record.ID)
		if contentErr != nil {
			ar.logger.Warn("async_review_content_recovery_failed", "job_id", record.ID, "error", contentErr)
		}
		if ruleContent == "" && !record.Sampled && plaintextHash(sample) == record.SHA256 {
			// Pre-v0.4 jobs stored only the reviewer input. It is safe to
			// reuse that value only when it was not sampled and its digest
			// proves it is the exact selected field.
			ruleContent = sample
		}
		if !ar.enqueue(asyncReviewJob{Hash: record.SHA256, Field: record.FieldName, Content: sample, RuleContent: ruleContent, Sampled: record.Sampled, Model: record.Model, APIKeyFingerprint: record.APIKeyFingerprint, APIKeyHint: record.APIKeyHint}) {
			return
		}
	}
}

func (ar *asyncRuntime) close() {
	close(ar.stop)
	<-ar.done
}

func (ar *asyncRuntime) process(job asyncReviewJob) {
	nodes := ar.snapshotNodes()
	if len(nodes) != 3 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	record, created, err := ar.store.CreateReviewJob(ctx, job.Hash, job.Hash, job.Field, job.Model, job.Content, job.RuleContent, job.Sampled, job.APIKeyFingerprint, job.APIKeyHint)
	if err != nil {
		ar.logger.Warn("async_review_job_create_failed", "sha256", job.Hash, "error", err)
		return
	}
	if !created {
		if record.Status == "promoted" || record.Status == "completed_no_quorum" || record.Status == "failed" {
			return
		}
		if sample, sampleErr := ar.store.LoadReviewJobSample(ctx, record.ID); sampleErr == nil && sample != "" {
			job.Content = sample
		}
		if content, contentErr := ar.store.LoadReviewJobContent(ctx, record.ID); contentErr == nil && content != "" {
			job.RuleContent = content
		}
		if job.RuleContent == "" && !record.Sampled && plaintextHash(job.Content) == record.SHA256 {
			job.RuleContent = job.Content
		}
		job.APIKeyFingerprint = record.APIKeyFingerprint
		job.APIKeyHint = record.APIKeyHint
	}
	claimed, err := ar.store.ClaimReviewJob(ctx, record.ID)
	if err != nil || !claimed {
		return
	}
	votes := audit.ReviewAsyncQuorum(ctx, nodes, audit.AIReviewRequest{Field: job.Field, Content: job.Content, Sampled: job.Sampled, Model: job.Model, Criteria: audit.DefaultEngineConfig().ReviewCriteria}, audit.DefaultRejectConfidence)
	for _, vote := range votes.Votes {
		row := storage.ReviewVote{JobID: record.ID, NodeSlot: vote.Slot, LatencyMS: vote.Latency.Milliseconds()}
		if vote.Err != nil {
			row.Error = vote.Err.Error()
		} else {
			row.Result = string(vote.Verdict.Result)
			row.Confidence = vote.Verdict.Confidence
			row.Reason = vote.Verdict.Reason
			row.Category = vote.Verdict.Category
		}
		if err := ar.store.RecordReviewVote(ctx, row); err != nil {
			ar.logger.Warn("async_vote_write_failed", "job_id", record.ID, "error", err)
		}
	}
	kind, promoted := votes.Kind, votes.Reached && !votes.Conflict
	if promoted {
		summary := makeVoteSummary(votes.Votes)
		if err := ar.store.PromoteHash(ctx, record.ID, job.Hash, kind, job.RuleContent, summary, job.APIKeyFingerprint, job.APIKeyHint); err != nil {
			ar.logger.Warn("async_rule_promotion_failed", "job_id", record.ID, "error", err)
			_ = ar.store.CompleteReviewJob(ctx, record.ID, "failed", "")
			return
		}
		_ = ar.store.CompleteReviewJob(ctx, record.ID, "promoted", kind)
		if ar.onPromotion != nil {
			reloadCtx, cancelReload := context.WithTimeout(context.Background(), 5*time.Second)
			if err := ar.onPromotion(reloadCtx); err != nil {
				ar.logger.Warn("async_rule_reload_failed", "error", err)
			}
			cancelReload()
		}
	} else {
		if record.Attempts+1 < 3 {
			delay := time.Duration(1<<record.Attempts) * 10 * time.Second
			_ = ar.store.ScheduleReviewRetry(ctx, record.ID, "quorum_not_reached", delay)
		} else {
			_ = ar.store.CompleteReviewJob(ctx, record.ID, "completed_no_quorum", "")
		}
	}
}

func makeVoteSummary(votes []audit.AsyncVote) string {
	parts := make([]string, 0, len(votes))
	for _, vote := range votes {
		if vote.Err != nil {
			parts = append(parts, vote.Slot+":error")
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%.3f", vote.Slot, vote.Verdict.Result, vote.Verdict.Confidence))
	}
	return strings.Join(parts, ",")
}

func plaintextHash(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration_error", "error", err)
		os.Exit(2)
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, cfg.DataDir, cfg.MasterKey)
	if err != nil {
		logger.Error("storage_open_error", "error", err)
		os.Exit(2)
	}
	defer store.Close()
	if err := store.EnsureAdmin(ctx, "admin", cfg.InitialAdminPass); err != nil {
		logger.Error("admin_init_error", "error", err)
		os.Exit(2)
	}
	seedProfiles(ctx, store)
	rt := &runtime{store: store, limiter: audit.NewFixedWindowLimiter(60, time.Minute), bulkhead: audit.NewConcurrencyGate(audit.DefaultAIConcurrency), fingerprintKey: append([]byte(nil), cfg.MasterKey...), trustedProxies: parseTrustedCIDRs(cfg.TrustedProxyCIDRs), events: make(chan audit.Event, 2048), logger: logger}
	rt.asyncRunner = newAsyncRuntime(store, logger)
	rt.asyncRunner.onPromotion = func(reloadCtx context.Context) error { return rt.reload(reloadCtx, logger) }
	rt.asyncRunner.start()
	defer rt.asyncRunner.close()
	rt.startEventWriter()
	defer rt.stopEventWriter()
	rt.cfg.Store(cfg)
	if err := rt.reload(ctx, logger); err != nil {
		logger.Error("audit_init_error", "error", err)
		os.Exit(2)
	}
	stopCleanup := rt.startCleanup()
	defer stopCleanup()

	storedConfig, err := store.GetConfig(ctx, cfg.UpstreamURL.String())
	if err != nil {
		logger.Error("proxy_config_error", "error", err)
		os.Exit(2)
	}
	upstream, err := url.Parse(storedConfig.UpstreamURL)
	if err != nil {
		logger.Error("proxy_upstream_error", "error", err)
		os.Exit(2)
	}
	public := &proxy.Server{
		Upstream:     upstream,
		MaxBody:      cfg.AuditBodyLimit,
		Logger:       logger,
		Auditor:      auditorAdapter{runtime: rt, logger: logger},
		Ready:        rt.ready,
		TrustedProxy: func(ip net.IP) bool { return trustedIP(ip, rt.trustedProxies) },
	}
	adminServer := &admin.Server{Store: store, Logger: logger, FixedUpstreamURL: cfg.UpstreamURL.String(), SecureCookies: cfg.AdminCookieSecure, StartedAt: time.Now(), UpdaterSocket: cfg.UpdaterSocket}
	adminServer.TestAI = testAIEndpoint
	adminServer.ValidateAIEndpoint = func(endpoint *url.URL) error {
		return config.ValidateEndpointAgainstListeners(endpoint, cfg.ListenAddr, cfg.AdminListenAddr)
	}
	adminServer.ValidateUpstream = func(endpoint *url.URL) error {
		return config.ValidateEndpointAgainstListeners(endpoint, cfg.ListenAddr, cfg.AdminListenAddr)
	}
	adminServer.FrameAncestors = rt.adminFrameAncestors
	adminServer.OnReload = func(reloadCtx context.Context) error {
		if err := rt.reload(reloadCtx, logger); err != nil {
			return err
		}
		latest, err := store.GetConfig(reloadCtx, cfg.UpstreamURL.String())
		if err != nil {
			return err
		}
		target, err := url.Parse(latest.UpstreamURL)
		if err != nil {
			return err
		}
		return public.SetUpstream(target)
	}
	dataHTTP := proxy.NewHTTPServer(cfg.ListenAddr, public.Handler())
	adminHTTP := proxy.NewHTTPServer(cfg.AdminListenAddr, adminServer.Handler())
	errCh := make(chan error, 2)
	go func() {
		logger.Info("data_plane_listening", "addr", cfg.ListenAddr, "upstream", upstream.String())
		errCh <- dataHTTP.ListenAndServe()
	}()
	go func() {
		logger.Info("admin_plane_listening", "addr", cfg.AdminListenAddr)
		errCh <- adminHTTP.ListenAndServe()
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-stop:
		logger.Info("shutdown_requested", "signal", sig.String())
	case e := <-errCh:
		if !errors.Is(e, http.ErrServerClosed) {
			logger.Error("server_error", "error", e)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = dataHTTP.Shutdown(shutdownCtx)
	_ = adminHTTP.Shutdown(shutdownCtx)
}

func (rt *runtime) reload(ctx context.Context, logger *slog.Logger) error {
	rt.reloadMu.Lock()
	defer rt.reloadMu.Unlock()
	cfgAny := rt.cfg.Load()
	cfg, ok := cfgAny.(config.Config)
	if !ok {
		return errors.New("runtime config unavailable")
	}
	stored, err := rt.store.GetConfig(ctx, cfg.UpstreamURL.String())
	if err != nil {
		return err
	}
	if stored.UpstreamURL == "" {
		stored.UpstreamURL = cfg.UpstreamURL.String()
	}
	profiles, err := rt.store.ListProfiles(ctx)
	if err != nil {
		return err
	}
	engineProfiles := make([]audit.ClientProfile, 0, len(profiles))
	for _, p := range profiles {
		matchers := make([]audit.Matcher, 0, len(p.Matchers))
		for _, m := range p.Matchers {
			matchers = append(matchers, audit.Matcher{Type: m.Type, Value: m.Value, CaseSensitive: m.CaseSensitive})
		}
		engineProfiles = append(engineProfiles, audit.ClientProfile{Key: profileKey(p), Name: p.Name, Description: p.Description, Enabled: p.Enabled, Priority: p.Priority, Matchers: matchers})
	}
	if len(engineProfiles) == 0 {
		engineProfiles = audit.DefaultClientProfiles()
	}
	endpoint, err := rt.store.GetAIEndpoint(ctx)
	if err != nil {
		return err
	}
	asyncNodes, err := rt.store.ListAINodes(ctx)
	if err != nil {
		return err
	}
	asyncReviewers := make([]audit.AsyncNodeReviewer, 0, len(asyncNodes))
	for _, node := range asyncNodes {
		if !node.Enabled || !node.HasAPIKey {
			continue
		}
		nodeURL, parseErr := url.Parse(node.BaseURL)
		if parseErr != nil {
			continue
		}
		if parseErr = config.ValidateEndpointAgainstListeners(nodeURL, cfg.ListenAddr, cfg.AdminListenAddr); parseErr != nil {
			logger.Warn("async_ai_node_disabled", "slot", node.Slot, "error", parseErr)
			continue
		}
		reviewer, reviewerErr := audit.NewOpenAIReviewer(audit.OpenAIReviewerConfig{BaseURL: node.BaseURL, Model: node.Model, APIKey: node.APIKey, Timeout: time.Duration(node.TimeoutMS) * time.Millisecond})
		if reviewerErr != nil {
			logger.Warn("async_ai_node_disabled", "slot", node.Slot, "error", reviewerErr)
			continue
		}
		asyncReviewers = append(asyncReviewers, audit.AsyncNodeReviewer{Slot: node.Slot, Reviewer: reviewer})
	}
	if rt.asyncRunner != nil {
		rt.asyncRunner.setNodes(asyncReviewers)
	}
	var reviewer audit.Reviewer
	if endpoint.BaseURL != "" && endpoint.Model != "" && endpoint.HasAPIKey {
		endpointURL, parseErr := url.Parse(endpoint.BaseURL)
		if parseErr == nil {
			parseErr = config.ValidateEndpointAgainstListeners(endpointURL, cfg.ListenAddr, cfg.AdminListenAddr)
		}
		if parseErr != nil {
			logger.Warn("ai_reviewer_disabled", "error", parseErr)
		} else {
			reviewer, err = audit.NewOpenAIReviewer(audit.OpenAIReviewerConfig{BaseURL: endpoint.BaseURL, Model: endpoint.Model, APIKey: endpoint.APIKey, Timeout: time.Duration(endpoint.TimeoutMS) * time.Millisecond})
		}
		if err != nil {
			logger.Warn("ai_reviewer_disabled", "error", err)
		}
	}
	engineCfg := audit.DefaultEngineConfig()
	engineCfg.Mode = audit.ModePermissive
	engineCfg.ProtectedPaths = stored.ProtectedPaths
	engineCfg.MaxBodyBytes = stored.MaxBodyBytes
	engineCfg.AITimeout = time.Duration(stored.RequestTimeoutMS) * time.Millisecond
	if endpoint.MaxConcurrency > 0 {
		engineCfg.AIConcurrency = endpoint.MaxConcurrency
	}
	engineCfg.Profiles = engineProfiles
	engineCfg.ReviewLimiter = rt.limiter
	engineCfg.AIBulkhead = rt.bulkhead
	if !stored.Enabled {
		engineCfg.Mode = audit.ModeOff
	}
	rules, err := rt.loadRules(ctx)
	if err != nil {
		return err
	}
	engine, err := audit.NewEngine(engineCfg, rules, reviewer, rt)
	if err != nil {
		return err
	}
	paths := make(map[string]struct{}, len(stored.ProtectedPaths))
	for _, p := range stored.ProtectedPaths {
		paths[p] = struct{}{}
	}
	rt.bulkhead.SetLimit(engineCfg.AIConcurrency)
	rt.state.Store(&runtimeState{engine: engine, paths: paths, rules: rules, adminFrameAncestors: append([]string(nil), stored.AdminFrameAncestors...), auditBodyLimit: stored.MaxBodyBytes, enabled: stored.Enabled})
	rt.cfg.Store(cfg)
	return nil
}

func (rt *runtime) adminFrameAncestors() []string {
	value := rt.state.Load()
	state, ok := value.(*runtimeState)
	if !ok || state == nil {
		return nil
	}
	return append([]string(nil), state.adminFrameAncestors...)
}

func (rt *runtime) ready(ctx context.Context) error {
	if rt.state.Load() == nil {
		return errors.New("audit runtime unavailable")
	}
	_, err := rt.store.GetConfig(ctx, "")
	return err
}

func profileKey(p storage.ClientProfile) string {
	switch p.Name {
	case "Codex VS Code":
		return "codex_vscode"
	case "Codex CLI":
		return "codex_cli"
	case "Codex Desktop":
		return "codex_desktop"
	}
	return fmt.Sprintf("profile_%d", p.ID)
}

func seedProfiles(ctx context.Context, store *storage.Store) {
	profiles, err := store.ListProfiles(ctx)
	if err != nil || len(profiles) > 0 {
		return
	}
	for _, p := range audit.DefaultClientProfiles() {
		matchers := make([]storage.ClientMatcher, 0, len(p.Matchers))
		for _, m := range p.Matchers {
			matchers = append(matchers, storage.ClientMatcher{Type: m.Type, Value: m.Value, CaseSensitive: m.CaseSensitive})
		}
		_, _ = store.SaveProfile(ctx, storage.ClientProfile{Name: p.Name, Description: p.Description, Enabled: p.Enabled, Priority: p.Priority, Matchers: matchers})
	}
}

type auditorAdapter struct {
	runtime *runtime
	logger  *slog.Logger
}

type runtimeStateContextKey struct{}

func (a auditorAdapter) requestState(req *http.Request, pin bool) *runtimeState {
	if req != nil {
		if state, ok := req.Context().Value(runtimeStateContextKey{}).(*runtimeState); ok {
			return state
		}
	}
	value := a.runtime.state.Load()
	state, _ := value.(*runtimeState)
	if pin && req != nil && state != nil {
		*req = *req.WithContext(context.WithValue(req.Context(), runtimeStateContextKey{}, state))
	}
	return state
}

func (a auditorAdapter) ShouldAudit(req *http.Request) bool {
	if req.Method != http.MethodPost {
		return false
	}
	state := a.requestState(req, true)
	if state == nil {
		return false
	}
	if !state.enabled {
		return false
	}
	_, found := state.paths[req.URL.Path]
	return found
}

func (a auditorAdapter) AuditBodyLimit(req *http.Request) int64 {
	if state := a.requestState(req, false); state != nil {
		return state.auditBodyLimit
	}
	return audit.DefaultMaxBodyBytes
}

func (a auditorAdapter) Evaluate(ctx context.Context, req *http.Request, body []byte) (proxy.Decision, error) {
	state := a.requestState(req, false)
	if state == nil {
		return proxy.Decision{Allow: true, Reason: string(audit.ReasonAIUnavailable)}, nil
	}
	if state.engine == nil {
		return proxy.Decision{Allow: true}, errors.New("audit runtime type invalid")
	}
	id := eventRequestID(req.Header.Get("X-Request-ID"))
	apiKeyFingerprint, apiKeyHint := a.apiKeyTrace(req.Header.Get("Authorization"))
	result := state.engine.Evaluate(ctx, audit.Request{ID: id, Method: req.Method, Path: boundedEventValue(req.URL.Path, 2048), Protocol: audit.ProtocolResponses, UserAgent: req.UserAgent(), Body: body, APIKeyFingerprint: apiKeyFingerprint, APIKeyHint: apiKeyHint, ClientIP: a.clientIP(req)})
	if result.Hash != "" && result.RuleContent != "" {
		kind := ""
		switch result.Reason {
		case audit.ReasonTrustedHashMatch:
			kind = "trusted"
		case audit.ReasonRiskHashMatch:
			kind = "risk"
		}
		if kind != "" {
			if err := a.runtime.store.StoreHashContext(ctx, kind, result.Hash, result.RuleContent, apiKeyFingerprint, apiKeyHint); err != nil {
				a.runtime.logger.Warn("hash_context_backfill_failed", "kind", kind, "sha256", result.Hash, "error", err)
			}
		}
	}
	// Async quorum review is deliberately detached from the request path. It
	// never changes the current decision and only promotes rules for later
	// requests after a complete vote is persisted.
	if a.runtime.asyncRunner != nil && result.Hash != "" && result.Field != "" && result.Reason != audit.ReasonTrustedHashMatch && result.Reason != audit.ReasonRiskHashMatch {
		if result.ReviewContent != "" {
			a.runtime.asyncRunner.enqueue(asyncReviewJob{Hash: result.Hash, Field: result.Field, Content: result.ReviewContent, RuleContent: result.RuleContent, Sampled: result.AISampled, Model: result.Model, APIKeyFingerprint: apiKeyFingerprint, APIKeyHint: apiKeyHint})
		}
	}
	return proxy.Decision{Allow: result.Allow, Blocked: result.Blocked, Reason: string(result.Reason), RequestID: id, AuditMs: result.AuditLatency.Milliseconds(), UAProfile: result.ProfileKey, Field: result.Field, Hash: result.Hash, Model: result.Model}, nil
}
func (a auditorAdapter) Observe(_ context.Context, req *http.Request, reason string) {
	id := eventRequestID(req.Header.Get("X-Request-ID"))
	apiKeyFingerprint, apiKeyHint := a.apiKeyTrace(req.Header.Get("Authorization"))
	_ = a.runtime.RecordAuditEvent(context.Background(), audit.Event{RequestID: id, Method: req.Method, Path: boundedEventValue(req.URL.Path, 2048), Protocol: "unreviewed", UserAgent: audit.SanitizeUserAgent(req.UserAgent()), APIKeyFingerprint: apiKeyFingerprint, APIKeyHint: apiKeyHint, Decision: "allow", Reason: audit.Reason(reason), CreatedAt: time.Now().UTC()})
}
func eventRequestID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return randomID()
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == ':') {
			return randomID()
		}
	}
	return value
}

func boundedEventValue(value string, maxBytes int) string {
	if value == "" || len(value) > maxBytes {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

var fallbackIDCounter atomic.Uint64

func randomID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	// Request IDs are observability identifiers rather than credentials. Keep
	// them unique enough to correlate a request even if the OS RNG is broken.
	return fmt.Sprintf("fallback-%x-%x", time.Now().UnixNano(), fallbackIDCounter.Add(1))
}

func (rt *runtime) loadRules(ctx context.Context) (ruleSnapshot, error) {
	trusted, err := rt.store.ListHashes(ctx, "trusted")
	if err != nil {
		return nil, err
	}
	risk, err := rt.store.ListHashes(ctx, "risk")
	if err != nil {
		return nil, err
	}
	rules := make(ruleSnapshot, len(trusted)+len(risk))
	for _, entry := range trusted {
		if entry.Enabled {
			rules[entry.SHA256] = audit.HashMatch{ID: entry.ID, SHA256: entry.SHA256, Kind: "trusted", Note: entry.Label}
		}
	}
	for _, entry := range risk {
		if entry.Enabled {
			rules[entry.SHA256] = audit.HashMatch{ID: entry.ID, SHA256: entry.SHA256, Kind: "risk", Note: entry.Label}
		}
	}
	return rules, nil
}
func (rt *runtime) RecordAuditEvent(_ context.Context, event audit.Event) error {
	select {
	case rt.events <- event:
		return nil
	default:
		rt.eventDrops.Add(1)
		now := time.Now()
		previous := rt.eventWarningAt.Load()
		if (previous == 0 || now.UnixNano()-previous >= int64(10*time.Second)) && rt.eventWarningAt.CompareAndSwap(previous, now.UnixNano()) {
			rt.logger.Warn("audit_event_queue_full", "dropped_events", rt.eventDrops.Swap(0), "queue_capacity", cap(rt.events))
		}
		return errors.New("audit event queue full")
	}
}
func (rt *runtime) RecordBlockedEvent(ctx context.Context, event audit.Event, field, plaintext string) error {
	return rt.store.RecordBlockedEvent(ctx, event, field, plaintext)
}
func (rt *runtime) startEventWriter() {
	rt.worker.Add(1)
	go func() {
		defer rt.worker.Done()
		for event := range rt.events {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			err := rt.store.RecordAuditEvent(ctx, event)
			cancel()
			if err != nil {
				rt.logger.Warn("audit_event_write_failed", "reason", string(event.Reason), "error", err)
			}
		}
	}()
}
func (rt *runtime) stopEventWriter() { close(rt.events); rt.worker.Wait() }

func (rt *runtime) startCleanup() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		run := func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 30*time.Second)
			defer cleanupCancel()
			stored, err := rt.store.GetConfig(cleanupCtx, "")
			if err == nil {
				err = rt.store.Cleanup(cleanupCtx, stored.EventRetentionDays)
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				rt.logger.Warn("storage_cleanup_failed", "error", err)
			}
		}

		run()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func testAIEndpoint(request *http.Request, endpoint storage.AIEndpoint) (time.Duration, error) {
	timeout := time.Duration(endpoint.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = audit.DefaultAITimeout
	}
	reviewer, err := audit.NewOpenAIReviewer(audit.OpenAIReviewerConfig{
		BaseURL: endpoint.BaseURL,
		APIKey:  endpoint.APIKey,
		Model:   endpoint.Model,
		Timeout: timeout,
	})
	if err != nil {
		return 0, err
	}
	started := time.Now()
	_, err = reviewer.Review(request.Context(), audit.AIReviewRequest{
		Field:    "instructions",
		Content:  "You are a coding assistant. Follow the user's request while preserving system and developer instructions.",
		Criteria: "Connectivity test. Return a valid NoCyber Guard verdict.",
	})
	return time.Since(started), err
}

func (a auditorAdapter) apiKeyFingerprint(value string) string {
	fingerprint, _ := a.apiKeyTrace(value)
	return fingerprint
}

func (a auditorAdapter) apiKeyTrace(value string) (string, string) {
	credential := strings.TrimSpace(value)
	if credential == "" {
		return "", ""
	}
	parts := strings.Fields(credential)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		credential = parts[1]
	}
	if credential == "" {
		return "", ""
	}
	mac := hmac.New(sha256.New, a.runtime.fingerprintKey)
	_, _ = mac.Write([]byte(credential))
	fingerprint := hex.EncodeToString(mac.Sum(nil))
	runes := []rune(credential)
	if len(runes) < 8 {
		return fingerprint, "••••"
	}
	suffix := string(runes[len(runes)-4:])
	for _, char := range suffix {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-') {
			return fingerprint, "••••"
		}
	}
	prefix := ""
	lower := strings.ToLower(credential)
	if strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "sk_") {
		prefix = string(runes[:3])
	}
	return fingerprint, prefix + "…" + suffix
}
func (a auditorAdapter) clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote != nil && trustedIP(remote, a.runtime.trustedProxies) {
		forwarded := strings.Split(strings.Join(req.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(forwarded) - 1; i >= 0; i-- {
			candidate := net.ParseIP(strings.TrimSpace(forwarded[i]))
			if candidate != nil && !trustedIP(candidate, a.runtime.trustedProxies) {
				return candidate.String()
			}
		}
	}
	if remote != nil {
		return remote.String()
	}
	return ""
}
func parseTrustedCIDRs(values []string) []*net.IPNet {
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err == nil {
			result = append(result, network)
		}
	}
	return result
}
func trustedIP(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
