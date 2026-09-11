package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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
	hash := map[string]any{"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "label": "test"}
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/trusted-hashes", hash)
	assertErrorCode(t, rr, http.StatusServiceUnavailable, "runtime_reload_failed")
}

func TestHashCRUD(t *testing.T) {
	_, handler, session, csrf := newAuthenticatedAdmin(t)
	reloads := 0
	handler.server.OnReload = func(context.Context) error { reloads++; return nil }
	hash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rr := adminRequest(t, handler.Handler(), session, csrf, http.MethodPost, "/api/v1/risk-hashes", map[string]any{"sha256": hash, "label": "before"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%q", rr.Code, rr.Body.String())
	}
	var created storage.HashEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodPut, "/api/v1/risk-hashes/"+strconv.FormatInt(created.ID, 10), map[string]any{"label": "after", "enabled": false})
	if rr.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%q", rr.Code, rr.Body.String())
	}
	var updated storage.HashEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Label != "after" || updated.Enabled {
		t.Fatalf("updated hash = %+v", updated)
	}
	rr = adminRequest(t, handler.Handler(), session, csrf, http.MethodDelete, "/api/v1/risk-hashes/"+strconv.FormatInt(created.ID, 10), nil)
	if rr.Code != http.StatusNoContent || reloads != 3 {
		t.Fatalf("delete status=%d reloads=%d body=%q", rr.Code, reloads, rr.Body.String())
	}
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
