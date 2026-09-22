package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abingooo/nocyber-guard/internal/audit"
	"github.com/abingooo/nocyber-guard/internal/config"
	"github.com/abingooo/nocyber-guard/internal/storage"
)

func TestAIEndpointValidationAppliesToSaveAndTest(t *testing.T) {
	store, handler, session, csrf := newAuthenticatedAdmin(t)
	server := handler.server
	server.ValidateAIEndpoint = func(endpoint *url.URL) error {
		return config.ValidateEndpointAgainstListeners(endpoint, ":8080", "127.0.0.1:9090")
	}
	testCalls := 0
	server.TestAI = func(_ *http.Request, endpoint storage.AIEndpoint) (time.Duration, error) {
		testCalls++
		if endpoint.BaseURL != "https://reviewer.example/v1" || endpoint.APIKey != "saved-secret" {
			t.Fatalf("unexpected test endpoint: %+v APIKey=%q", endpoint, endpoint.APIKey)
		}
		return 12 * time.Millisecond, nil
	}

	valid := map[string]any{
		"base_url": "https://reviewer.example/v1", "model": "guard-model",
		"api_key": "saved-secret", "timeout_ms": 15000, "max_concurrency": 16,
	}
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/ai-endpoint", valid)
	if rr.Code != http.StatusOK {
		t.Fatalf("valid save status=%d body=%q", rr.Code, rr.Body.String())
	}

	testInput := map[string]any{
		"base_url": "https://reviewer.example/v1", "model": "guard-model",
		"api_key": "", "has_api_key": true, "timeout_ms": 15000, "max_concurrency": 16,
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/ai-endpoint/test", testInput)
	if rr.Code != http.StatusOK || testCalls != 1 {
		t.Fatalf("valid test status=%d calls=%d body=%q", rr.Code, testCalls, rr.Body.String())
	}

	loopback := map[string]any{
		"base_url": "http://127.0.0.1:8080/v1", "model": "guard-model",
		"api_key": "replacement-secret", "timeout_ms": 15000, "max_concurrency": 16,
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/ai-endpoint", loopback)
	assertInvalidAIEndpoint(t, rr)
	saved, err := store.GetAIEndpoint(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if saved.BaseURL != "https://reviewer.example/v1" || saved.APIKey != "saved-secret" {
		t.Fatalf("rejected endpoint changed storage: %+v APIKey=%q", saved, saved.APIKey)
	}

	loopback["api_key"] = ""
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/ai-endpoint/test", loopback)
	assertInvalidAIEndpoint(t, rr)
	if testCalls != 1 {
		t.Fatalf("loopback test reached network callback; calls=%d", testCalls)
	}

	invalidLimits := map[string]any{
		"base_url": "https://reviewer.example/v1", "model": "guard-model",
		"api_key": "", "timeout_ms": 15000, "max_concurrency": 257,
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/ai-endpoint", invalidLimits)
	assertErrorCode(t, rr, http.StatusBadRequest, "invalid_ai_config")
}

func TestAsyncNodesAcceptSecretsButNeverReturnThem(t *testing.T) {
	store, handler, session, csrf := newAuthenticatedAdmin(t)
	input := map[string]any{"nodes": []map[string]any{
		{"slot": "async_1", "name": "one", "base_url": "https://one.example/v1", "model": "m1", "api_key": "secret-one", "timeout_ms": 15000, "enabled": true},
		{"slot": "async_2", "name": "two", "base_url": "https://two.example/v1", "model": "m2", "api_key": "secret-two", "timeout_ms": 15000, "enabled": true},
		{"slot": "async_3", "name": "three", "base_url": "https://three.example/v1", "model": "m3", "api_key": "secret-three", "timeout_ms": 15000, "enabled": true},
	}}
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/ai-nodes", input)
	if rr.Code != http.StatusOK || bytes.Contains(rr.Body.Bytes(), []byte("secret-one")) {
		t.Fatalf("async node response status=%d body=%q", rr.Code, rr.Body.String())
	}
	nodes, err := store.ListAINodes(context.Background())
	if err != nil || len(nodes) != 3 || nodes[0].APIKey == "" {
		t.Fatalf("stored async nodes=%+v err=%v", nodes, err)
	}
	wantKeys := make(map[string]string, len(nodes))
	for _, node := range nodes {
		wantKeys[node.Slot] = node.APIKey
	}
	for _, node := range input["nodes"].([]map[string]any) {
		node["api_key"] = ""
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/ai-nodes", input)
	if rr.Code != http.StatusOK || bytes.Contains(rr.Body.Bytes(), []byte("secret-")) {
		t.Fatalf("async node key-preserving save status=%d body=%q", rr.Code, rr.Body.String())
	}
	nodes, err = store.ListAINodes(context.Background())
	if err != nil || len(nodes) != 3 {
		t.Fatalf("stored async nodes after blank-key save=%+v err=%v", nodes, err)
	}
	for _, node := range nodes {
		if node.APIKey != wantKeys[node.Slot] {
			t.Fatalf("async node %s API key changed after blank-key save", node.Slot)
		}
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodGet, "/api/v1/ai-nodes", nil)
	if rr.Code != http.StatusOK || bytes.Contains(rr.Body.Bytes(), []byte("secret-")) {
		t.Fatalf("async node GET status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestAsyncNodeTestUsesUnsavedFormAndPreservesStoredSecret(t *testing.T) {
	_, handler, session, csrf := newAuthenticatedAdmin(t)
	calls := 0
	handler.server.TestAI = func(_ *http.Request, endpoint storage.AIEndpoint) (time.Duration, error) {
		calls++
		if endpoint.BaseURL != "https://draft.example/v1" || endpoint.Model != "draft-model" || endpoint.MaxConcurrency != 1 {
			t.Fatalf("unexpected async test endpoint: %+v", endpoint)
		}
		wantKey := "draft-secret"
		if calls > 1 {
			wantKey = "stored-secret"
		}
		if endpoint.APIKey != wantKey {
			t.Fatalf("async test API key=%q want %q", endpoint.APIKey, wantKey)
		}
		return 9 * time.Millisecond, nil
	}

	draft := map[string]any{
		"slot": "async_1", "name": "draft", "base_url": "https://draft.example/v1",
		"model": "draft-model", "api_key": "draft-secret", "timeout_ms": 15000, "enabled": true,
	}
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/ai-nodes/async_1/test", draft)
	if rr.Code != http.StatusOK || calls != 1 {
		t.Fatalf("unsaved async test status=%d calls=%d body=%q", rr.Code, calls, rr.Body.String())
	}

	input := map[string]any{"nodes": []map[string]any{
		{"slot": "async_1", "name": "one", "base_url": "https://draft.example/v1", "model": "draft-model", "api_key": "stored-secret", "timeout_ms": 15000, "enabled": true},
		{"slot": "async_2", "name": "two", "base_url": "https://two.example/v1", "model": "m2", "api_key": "secret-two", "timeout_ms": 15000, "enabled": true},
		{"slot": "async_3", "name": "three", "base_url": "https://three.example/v1", "model": "m3", "api_key": "secret-three", "timeout_ms": 15000, "enabled": true},
	}}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/ai-nodes", input)
	if rr.Code != http.StatusOK {
		t.Fatalf("async node setup status=%d body=%q", rr.Code, rr.Body.String())
	}

	draft["api_key"] = ""
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/ai-nodes/async_1/test", draft)
	if rr.Code != http.StatusOK || calls != 2 {
		t.Fatalf("async test with stored key status=%d calls=%d body=%q", rr.Code, calls, rr.Body.String())
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/ai-nodes/async_1/test", map[string]any{})
	if rr.Code != http.StatusOK || calls != 3 {
		t.Fatalf("legacy stored async test status=%d calls=%d body=%q", rr.Code, calls, rr.Body.String())
	}

	draft["slot"] = "async_2"
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/ai-nodes/async_1/test", draft)
	assertErrorCode(t, rr, http.StatusBadRequest, "invalid_ai_node")
	if calls != 3 {
		t.Fatalf("mismatched slot reached test callback; calls=%d", calls)
	}
}

func TestConfigUsesFixedUpstreamAndRejectsInvalidUpdates(t *testing.T) {
	store, handler, session, csrf := newAuthenticatedAdmin(t)
	ctx := context.Background()
	initial, err := store.GetConfig(ctx, handler.server.FixedUpstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	initial.Enabled = false
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/config", configUpdate(initial))
	if rr.Code != http.StatusOK {
		t.Fatalf("valid config status=%d body=%q", rr.Code, rr.Body.String())
	}

	current, err := store.GetConfig(ctx, handler.server.FixedUpstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	changedUpstream := current
	changedUpstream.UpstreamURL = "https://attacker.example"
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/config", configUpdate(changedUpstream))
	assertErrorCode(t, rr, http.StatusBadRequest, "upstream_immutable")

	invalid := current
	invalid.ProtectedPaths = []string{"/v1/responses/../messages"}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/config", configUpdate(invalid))
	assertErrorCode(t, rr, http.StatusBadRequest, "invalid_config")

	after, err := store.GetConfig(ctx, handler.server.FixedUpstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != current.Version || after.UpstreamURL != handler.server.FixedUpstreamURL {
		t.Fatalf("rejected config changed state: before=%+v after=%+v", current, after)
	}
}

func TestConfigRequiresExpectedVersionAndRejectsStaleUpdate(t *testing.T) {
	store, handler, session, csrf := newAuthenticatedAdmin(t)
	current, err := store.GetConfig(context.Background(), handler.server.FixedUpstreamURL)
	if err != nil {
		t.Fatal(err)
	}

	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/config", current)
	assertErrorCode(t, rr, http.StatusBadRequest, "expected_version_required")

	payload := configUpdate(current)
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/config", payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("first update status=%d body=%q", rr.Code, rr.Body.String())
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/config", payload)
	assertErrorCode(t, rr, http.StatusConflict, "version_conflict")
}

func TestMutationReportsRuntimeReloadFailure(t *testing.T) {
	_, handler, session, csrf := newAuthenticatedAdmin(t)
	handler.server.OnReload = func(context.Context) error { return errors.New("reload unavailable") }
	content := "reload failure rule"
	digest := sha256.Sum256([]byte(content))
	hash := map[string]any{"sha256": hex.EncodeToString(digest[:]), "label": "test", "content": content}
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/trusted-hashes", hash)
	assertErrorCode(t, rr, http.StatusServiceUnavailable, "runtime_reload_failed")
}

func TestHashCRUD(t *testing.T) {
	_, handler, session, csrf := newAuthenticatedAdmin(t)
	reloads := 0
	handler.server.OnReload = func(context.Context) error { reloads++; return nil }
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/risk-hashes", map[string]any{"sha256": strings.Repeat("a", 64), "label": "missing plaintext"})
	assertErrorCode(t, rr, http.StatusBadRequest, "rule_content_required")
	content := "  风险规则原文\n保留换行  "
	digest := sha256.Sum256([]byte(content))
	hash := hex.EncodeToString(digest[:])
	fingerprint := strings.Repeat("e", 64)
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/risk-hashes", map[string]any{"sha256": "", "label": "before", "content": content, "api_key_fingerprint": fingerprint, "api_key_hint": "sk-…7A9C"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%q", rr.Code, rr.Body.String())
	}
	var created storage.HashEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.SHA256 != hash || created.Content != content || created.APIKeyFingerprint != fingerprint || created.APIKeyHint != "sk-…7A9C" || created.APIKeySeenAt == "" {
		t.Fatalf("created hash plaintext = %+v", created)
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodGet, "/api/v1/risk-hashes", nil)
	if rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte("风险规则原文")) {
		t.Fatalf("list plaintext status=%d body=%q", rr.Code, rr.Body.String())
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/risk-hashes/"+strconv.FormatInt(created.ID, 10), map[string]any{"label": "after", "enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%q", rr.Code, rr.Body.String())
	}
	var updated storage.HashEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Label != "after" || updated.Enabled || updated.Content != content {
		t.Fatalf("updated hash = %+v", updated)
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodDelete, "/api/v1/risk-hashes/"+strconv.FormatInt(created.ID, 10), nil)
	if rr.Code != http.StatusNoContent || reloads != 3 {
		t.Fatalf("delete status=%d reloads=%d body=%q", rr.Code, reloads, rr.Body.String())
	}
}

func TestHashPlaintextCanBeBackfilledWithoutExtraCredential(t *testing.T) {
	store, handler, session, csrf := newAuthenticatedAdmin(t)
	content := "legacy hash plaintext"
	digest := sha256.Sum256([]byte(content))
	hash := hex.EncodeToString(digest[:])
	legacy, err := store.AddHash(context.Background(), "trusted", hash, "legacy")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"label": legacy.Label, "enabled": true, "content": content}
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/trusted-hashes/"+strconv.FormatInt(legacy.ID, 10), payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("plaintext backfill status=%d body=%q", rr.Code, rr.Body.String())
	}
	var updated storage.HashEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil || updated.Content != content {
		t.Fatalf("plaintext backfill = (%+v, %v)", updated, err)
	}
	payload["content"] = "wrong plaintext"
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/trusted-hashes/"+strconv.FormatInt(legacy.ID, 10), payload)
	assertErrorCode(t, rr, http.StatusBadRequest, "invalid_hash")
}

func TestAdminAPIRequiresSessionAndCSRF(t *testing.T) {
	_, handler, session, _ := newAuthenticatedAdmin(t)
	h := handler.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
	assertErrorCode(t, rr, http.StatusUnauthorized, "unauthorized")

	req := httptest.NewRequest(http.MethodPut, "/api/v1/config", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(session)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assertErrorCode(t, rr, http.StatusForbidden, "csrf_failed")
}

func TestEventsDateFiltersAreAppliedAndValidated(t *testing.T) {
	store, handler, session, _ := newAuthenticatedAdmin(t)
	ctx := context.Background()
	for _, item := range []struct {
		id string
		at time.Time
	}{
		{"admin-before", time.Date(2026, 9, 9, 23, 59, 59, 0, time.UTC)},
		{"admin-start", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)},
		{"admin-end", time.Date(2026, 9, 10, 23, 59, 59, 999999999, time.UTC)},
		{"admin-after", time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)},
	} {
		event := audit.Event{
			RequestID: item.id, Method: http.MethodPost, Path: "/v1/responses", Protocol: audit.ProtocolResponses,
			Model: "test", UserAgent: "test", ProfileKey: "other", Decision: "allow", Reason: audit.ReasonAIPass,
			CreatedAt: item.at,
		}
		if err := store.RecordAuditEvent(ctx, event); err != nil {
			t.Fatalf("RecordAuditEvent(%s): %v", item.id, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/events?page=1&page_size=20&from=2026-09-10&to=2026-09-10", nil)
	req.AddCookie(session)
	rr := httptest.NewRecorder()
	handler.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("date-filter status=%d body=%q", rr.Code, rr.Body.String())
	}
	var response struct {
		Items []storage.Event `json:"items"`
		Total int64           `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode date-filter response: %v", err)
	}
	if response.Total != 2 || len(response.Items) != 2 || response.Items[0].RequestID != "admin-end" || response.Items[1].RequestID != "admin-start" {
		t.Fatalf("date-filter response = %+v, want admin-end/admin-start", response)
	}
	for _, rawURL := range []string{
		"/api/v1/events?from=2026-02-30",
		"/api/v1/events?to=2026/09/10",
		"/api/v1/events?from=2026-09-11&to=2026-09-10",
	} {
		req = httptest.NewRequest(http.MethodGet, rawURL, nil)
		req.AddCookie(session)
		rr = httptest.NewRecorder()
		handler.Handler().ServeHTTP(rr, req)
		assertErrorCode(t, rr, http.StatusBadRequest, "invalid_event_date")
	}
}

func TestParseEventCleanupCutoffAcceptsBrowserLocalMidnight(t *testing.T) {
	cutoff, err := parseEventCleanupCutoff("2026-09-22T00:00:00+08:00")
	if err != nil {
		t.Fatalf("parseEventCleanupCutoff: %v", err)
	}
	want := time.Date(2026, 9, 21, 16, 0, 0, 0, time.UTC)
	if !cutoff.Equal(want) {
		t.Fatalf("cutoff = %s, want %s", cutoff, want)
	}
	if _, err := parseEventCleanupCutoff("2026-02-30"); err == nil {
		t.Fatal("invalid cleanup date was accepted")
	}
}

func TestAdminCanDeleteSingleAndBulkEvents(t *testing.T) {
	store, handler, session, csrf := newAuthenticatedAdmin(t)
	ctx := context.Background()
	old := audit.Event{
		RequestID: "admin-cleanup-old", Method: http.MethodPost, Path: "/v1/responses", Protocol: audit.ProtocolResponses,
		Model: "test", UserAgent: "test", ProfileKey: "other", Decision: "block", Reason: audit.ReasonRiskHashMatch,
		CreatedAt: time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC),
	}
	if err := store.RecordBlockedEvent(ctx, old, "instructions", "admin cleanup evidence"); err != nil {
		t.Fatalf("RecordBlockedEvent: %v", err)
	}
	recent := old
	recent.RequestID = "admin-cleanup-recent"
	recent.Decision = "allow"
	recent.Reason = audit.ReasonAIPass
	recent.CreatedAt = time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	if err := store.RecordAuditEvent(ctx, recent); err != nil {
		t.Fatalf("RecordAuditEvent: %v", err)
	}

	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodDelete, "/api/v1/events", map[string]any{"scope": "before", "before": "2026-09-10"})
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk delete status=%d body=%q", rr.Code, rr.Body.String())
	}
	var deleted storage.EventDeleteResult
	if err := json.Unmarshal(rr.Body.Bytes(), &deleted); err != nil {
		t.Fatalf("decode bulk delete response: %v", err)
	}
	if deleted.DeletedEvents != 1 || deleted.DeletedEvidence != 1 {
		t.Fatalf("bulk delete response = %+v", deleted)
	}
	items, total, err := store.ListEvents(ctx, 1, 20, "", "")
	if err != nil || total != 1 || len(items) != 1 || items[0].RequestID != recent.RequestID {
		t.Fatalf("remaining events = (%+v, %d, %v)", items, total, err)
	}

	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodDelete, "/api/v1/events/"+strconv.FormatInt(items[0].ID, 10), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("single delete status=%d body=%q", rr.Code, rr.Body.String())
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodDelete, "/api/v1/events/"+strconv.FormatInt(items[0].ID, 10), nil)
	assertErrorCode(t, rr, http.StatusNotFound, "event_not_found")

	for _, input := range []map[string]any{
		{"scope": "before", "before": ""},
		{"scope": "all", "before": "2026-09-10"},
		{"scope": "filtered"},
	} {
		rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodDelete, "/api/v1/events", input)
		assertErrorCode(t, rr, http.StatusBadRequest, "invalid_event_cleanup")
	}
}

type authenticatedAdmin struct {
	server *Server
}

func (a *authenticatedAdmin) Handler() http.Handler { return a.server.Handler() }

func newAuthenticatedAdmin(t *testing.T) (*storage.Store, *authenticatedAdmin, *http.Cookie, string) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, t.TempDir(), []byte("admin-test-master-key"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.EnsureAdmin(ctx, "admin", "test-password"); err != nil {
		t.Fatal(err)
	}
	admin := &authenticatedAdmin{server: &Server{Store: store, FixedUpstreamURL: "https://upstream.example"}}
	loginBody := bytes.NewBufferString(`{"username":"admin","password":"test-password"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginBody)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	admin.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%q", rr.Code, rr.Body.String())
	}
	var session *http.Cookie
	var csrf string
	for _, cookie := range rr.Result().Cookies() {
		switch cookie.Name {
		case sessionCookie:
			session = cookie
		case csrfCookie:
			csrf = cookie.Value
		}
	}
	if session == nil || csrf == "" {
		t.Fatal("login did not return session and CSRF cookies")
	}
	return store, admin, session, csrf
}

func adminRequest(t *testing.T, handler http.Handler, session *http.Cookie, csrf, method, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(session)
	req.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrf})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func configUpdate(config storage.Config) map[string]any {
	encoded, _ := json.Marshal(config)
	var payload map[string]any
	_ = json.Unmarshal(encoded, &payload)
	payload["expected_version"] = config.Version
	return payload
}

func assertInvalidAIEndpoint(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400; body=%q", rr.Code, rr.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body.Error.Code != "invalid_ai_endpoint" {
		t.Fatalf("error code=%q body=%q", body.Error.Code, rr.Body.String())
	}
}

func assertErrorCode(t *testing.T, rr *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("status=%d, want %d; body=%q", rr.Code, status, rr.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body.Error.Code != code {
		t.Fatalf("error code=%q, want %q; body=%q", body.Error.Code, code, rr.Body.String())
	}
}
