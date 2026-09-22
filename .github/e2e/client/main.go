package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"
)

const websocketGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

type suite struct {
	guardURL    string
	adminURL    string
	upstreamURL string
	password    string
	dataClient  *http.Client
	adminClient *http.Client
	csrf        string
}

type echoResponse struct {
	Method          string   `json:"method"`
	RequestURI      string   `json:"request_uri"`
	EscapedPath     string   `json:"escaped_path"`
	BodySHA256      string   `json:"body_sha256"`
	BodyLength      int      `json:"body_length"`
	MultiHeader     []string `json:"multi_header"`
	Cookie          string   `json:"cookie"`
	AuthorizationOK bool     `json:"authorization_ok"`
	ForwardedFor    []string `json:"forwarded_for"`
	ForwardedProto  []string `json:"forwarded_proto"`
	ForwardedHost   []string `json:"forwarded_host"`
	ForwardedPort   []string `json:"forwarded_port"`
}

type upstreamStats struct {
	Total  int            `json:"total"`
	Routes map[string]int `json:"routes"`
}

type event struct {
	ID                int64  `json:"id"`
	Path              string `json:"path"`
	Decision          string `json:"decision"`
	Action            string `json:"action"`
	Outcome           string `json:"outcome"`
	Reason            string `json:"reason"`
	FieldName         string `json:"field_name"`
	ClientProfile     string `json:"client_profile"`
	APIKeyFingerprint string `json:"api_key_fingerprint"`
	APIKeyHint        string `json:"api_key_hint"`
	PromptSHA256      string `json:"prompt_sha256"`
	UpstreamAccessed  bool   `json:"upstream_accessed"`
	EvidenceAvailable bool   `json:"evidence_available"`
}

func main() {
	mode := "primary"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	testSuite, err := newSuite()
	if err == nil {
		switch mode {
		case "primary":
			err = testSuite.runPrimary()
		case "persistence":
			err = testSuite.runPersistence()
		default:
			err = fmt.Errorf("unknown test mode %q", mode)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "compose E2E failed:", err)
		os.Exit(1)
	}
	fmt.Printf("compose E2E %s checks passed\n", mode)
}

func newSuite() (*suite, error) {
	guardURL, err := requiredURL("NCG_E2E_GUARD_URL")
	if err != nil {
		return nil, err
	}
	adminURL, err := requiredURL("NCG_E2E_ADMIN_URL")
	if err != nil {
		return nil, err
	}
	upstreamURL, err := requiredURL("NCG_E2E_UPSTREAM_URL")
	if err != nil {
		return nil, err
	}
	password := os.Getenv("NCG_E2E_ADMIN_PASSWORD")
	if password == "" {
		return nil, errors.New("NCG_E2E_ADMIN_PASSWORD is required")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	noRedirect := func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &suite{
		guardURL:    guardURL,
		adminURL:    adminURL,
		upstreamURL: upstreamURL,
		password:    password,
		dataClient:  &http.Client{Timeout: 8 * time.Second, CheckRedirect: noRedirect},
		adminClient: &http.Client{Timeout: 8 * time.Second, CheckRedirect: noRedirect, Jar: jar},
	}, nil
}

func requiredURL(name string) (string, error) {
	value := strings.TrimRight(strings.TrimSpace(os.Getenv(name)), "/")
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return "", fmt.Errorf("%s must be an absolute HTTP URL", name)
	}
	return value, nil
}

func (s *suite) runPrimary() error {
	if err := s.checkHealthAndUI(); err != nil {
		return err
	}
	if err := s.checkTransparentEcho(); err != nil {
		return err
	}
	if err := s.checkBypassRequests(); err != nil {
		return err
	}
	if err := s.checkNativeResponses(); err != nil {
		return err
	}
	if err := s.checkSSE(); err != nil {
		return err
	}
	if err := checkWebSocket(s.guardURL); err != nil {
		return err
	}
	if err := s.login(); err != nil {
		return err
	}
	if err := s.checkAdminSettings(); err != nil {
		return err
	}
	if err := s.checkRiskBlock(); err != nil {
		return err
	}
	if err := s.checkAuditedFailOpen(); err != nil {
		return err
	}
	return s.checkEventCleanup()
}

func (s *suite) checkEventCleanup() error {
	response, body, _, err := s.adminJSON(http.MethodGet, "/api/v1/events?page=1&page_size=200", nil)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("event list before cleanup failed: status=%d err=%v", responseStatus(response), err)
	}
	var before struct {
		Items []event `json:"items"`
		Total int64   `json:"total"`
	}
	if json.Unmarshal(body, &before) != nil || before.Total == 0 {
		return fmt.Errorf("event list before cleanup was empty or invalid: %s", body)
	}

	response, body, _, err = s.adminJSON(http.MethodDelete, "/api/v1/events", mustJSON(map[string]any{"scope": "all"}))
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("event cleanup failed: status=%d err=%v body=%s", responseStatus(response), err, body)
	}
	var deleted struct {
		Events   int64 `json:"deleted_events"`
		Evidence int64 `json:"deleted_evidence"`
	}
	if json.Unmarshal(body, &deleted) != nil || deleted.Events != before.Total || deleted.Evidence == 0 {
		return fmt.Errorf("event cleanup counts are invalid: before=%d response=%s", before.Total, body)
	}

	response, body, _, err = s.adminJSON(http.MethodGet, "/api/v1/events?page=1&page_size=20", nil)
	if err != nil || response.StatusCode != http.StatusOK {
		return fmt.Errorf("event list after cleanup failed: status=%d err=%v", responseStatus(response), err)
	}
	var after struct {
		Total int64 `json:"total"`
	}
	if json.Unmarshal(body, &after) != nil || after.Total != 0 {
		return fmt.Errorf("events remained after cleanup: %s", body)
	}
	return nil
}

func (s *suite) checkAdminSettings() error {
	syncNode := map[string]any{
		"base_url": s.upstreamURL + "/v1", "model": "e2e-reviewer", "api_key": "e2e-sync-secret",
		"timeout_ms": 15000, "max_concurrency": 4,
	}
	response, body, _, err := s.adminJSON(http.MethodPut, "/api/v1/ai-endpoint", mustJSON(syncNode))
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("e2e-sync-secret")) {
		return fmt.Errorf("synchronous AI node save failed: status=%d err=%v", responseStatus(response), err)
	}
	syncNode["api_key"] = ""
	response, body, _, err = s.adminJSON(http.MethodPost, "/api/v1/ai-endpoint/test", mustJSON(syncNode))
	if err != nil || response.StatusCode != http.StatusOK || !jsonOK(body) {
		return fmt.Errorf("synchronous AI node test failed: status=%d err=%v body=%s", responseStatus(response), err, body)
	}

	draft := map[string]any{
		"slot": "async_1", "name": "draft", "base_url": s.upstreamURL + "/v1", "model": "e2e-reviewer",
		"api_key": "e2e-draft-secret", "timeout_ms": 15000, "enabled": true,
	}
	response, body, _, err = s.adminJSON(http.MethodPost, "/api/v1/ai-nodes/async_1/test", mustJSON(draft))
	if err != nil || response.StatusCode != http.StatusOK || !jsonOK(body) {
		return fmt.Errorf("unsaved asynchronous AI node test failed: status=%d err=%v body=%s", responseStatus(response), err, body)
	}

	nodes := []map[string]any{}
	for index, slot := range []string{"async_1", "async_2", "async_3"} {
		nodes = append(nodes, map[string]any{
			"slot": slot, "name": fmt.Sprintf("node %d", index+1), "base_url": s.upstreamURL + "/v1",
			"model": "e2e-reviewer", "api_key": fmt.Sprintf("e2e-async-%d", index+1), "timeout_ms": 15000, "enabled": true,
		})
	}
	response, body, _, err = s.adminJSON(http.MethodPut, "/api/v1/ai-nodes", mustJSON(map[string]any{"nodes": nodes}))
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("e2e-async-")) {
		return fmt.Errorf("asynchronous AI node save failed: status=%d err=%v", responseStatus(response), err)
	}
	for _, node := range nodes {
		node["api_key"] = ""
	}
	response, body, _, err = s.adminJSON(http.MethodPut, "/api/v1/ai-nodes", mustJSON(map[string]any{"nodes": nodes}))
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("e2e-async-")) {
		return fmt.Errorf("asynchronous AI key-preserving save failed: status=%d err=%v body=%s", responseStatus(response), err, body)
	}
	response, body, _, err = s.adminJSON(http.MethodPost, "/api/v1/ai-nodes/async_1/test", mustJSON(nodes[0]))
	if err != nil || response.StatusCode != http.StatusOK || !jsonOK(body) {
		return fmt.Errorf("saved asynchronous AI node test failed: status=%d err=%v body=%s", responseStatus(response), err, body)
	}
	response, body, _, err = s.adminJSON(http.MethodGet, "/api/v1/ai-nodes", nil)
	if err != nil || response.StatusCode != http.StatusOK || bytes.Contains(body, []byte("e2e-async-")) || !bytes.Contains(body, []byte(`"has_api_key":true`)) {
		return fmt.Errorf("asynchronous AI node readback failed: status=%d err=%v", responseStatus(response), err)
	}
	return nil
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

func jsonOK(body []byte) bool {
	var value struct {
		OK bool `json:"ok"`
	}
	return json.Unmarshal(body, &value) == nil && value.OK
}

func responseStatus(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func (s *suite) runPersistence() error {
	if err := s.checkHealthAndUI(); err != nil {
		return err
	}
	if err := s.login(); err != nil {
		return err
	}
	before, err := s.stats()
	if err != nil {
		return err
	}
	if err := s.expectBlocked(guardedPrompt()); err != nil {
		return fmt.Errorf("persisted risk rule was not enforced: %w", err)
	}
	after, err := s.stats()
	if err != nil {
		return err
	}
	if routeCount(before, "POST /v1/responses") != routeCount(after, "POST /v1/responses") {
		return errors.New("persisted block reached the upstream")
	}
	return nil
}

func (s *suite) checkHealthAndUI() error {
	for _, endpoint := range []string{
		s.guardURL + "/_nocyber/healthz",
		s.guardURL + "/_nocyber/readyz",
		s.adminURL + "/_nocyber/readyz",
	} {
		response, body, err := s.request(s.dataClient, http.MethodGet, endpoint, nil, nil)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"status"`)) {
			return errors.New("health or readiness endpoint failed")
		}
	}
	response, body, err := s.request(s.dataClient, http.MethodGet, s.adminURL+"/", nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Type"), "text/html") ||
		!bytes.Contains(bytes.ToLower(body), []byte("nocyber")) {
		return errors.New("embedded admin UI was not served")
	}
	return nil
}

func (s *suite) checkTransparentEcho() error {
	payload := []byte(`{"payload":"transparent","sequence":17}`)
	direct, err := s.echo(s.upstreamURL, payload)
	if err != nil {
		return fmt.Errorf("direct echo: %w", err)
	}
	guarded, err := s.echo(s.guardURL, payload)
	if err != nil {
		return fmt.Errorf("guarded echo: %w", err)
	}
	if direct.Method != guarded.Method || direct.RequestURI != guarded.RequestURI ||
		direct.EscapedPath != guarded.EscapedPath || direct.BodySHA256 != guarded.BodySHA256 ||
		direct.BodyLength != guarded.BodyLength || !reflect.DeepEqual(direct.MultiHeader, guarded.MultiHeader) ||
		direct.Cookie != guarded.Cookie || !guarded.AuthorizationOK {
		return errors.New("guarded request differs from direct request")
	}
	if guarded.RequestURI != "/echo/a%2Fb?alpha=one%20two&alpha=three" {
		return errors.New("RawPath or query was not preserved")
	}
	if !reflect.DeepEqual(guarded.MultiHeader, []string{"first", "second"}) || guarded.Cookie != "session=e2e; theme=dark" {
		return errors.New("multi-value header or Cookie was not preserved")
	}
	if containsForwardedValue(guarded.ForwardedFor, "203.0.113.99") || len(guarded.ForwardedFor) == 0 {
		return errors.New("untrusted forwarding metadata was not sanitized")
	}
	if !reflect.DeepEqual(guarded.ForwardedProto, []string{"http"}) ||
		!reflect.DeepEqual(guarded.ForwardedPort, []string{"8080"}) {
		return errors.New("derived forwarding metadata is invalid")
	}
	return nil
}

func (s *suite) echo(base string, payload []byte) (echoResponse, error) {
	headers := http.Header{
		"Authorization":    []string{"Bearer e2e-forwarded-token"},
		"Cookie":           []string{"session=e2e; theme=dark"},
		"User-Agent":       []string{"e2e-transparent-client/1"},
		"X-E2E-Multi":      []string{"first", "second"},
		"X-Forwarded-For":  []string{"203.0.113.99"},
		"X-Forwarded-Host": []string{"spoofed.invalid"},
	}
	response, body, err := s.request(s.dataClient, http.MethodPost, base+"/echo/a%2Fb?alpha=one%20two&alpha=three", payload, headers)
	if err != nil {
		return echoResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		return echoResponse{}, fmt.Errorf("echo returned status %d", response.StatusCode)
	}
	var result echoResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return echoResponse{}, errors.New("echo returned invalid JSON")
	}
	return result, nil
}

func (s *suite) checkBypassRequests() error {
	cases := []struct {
		path      string
		userAgent string
		body      []byte
	}{
		{path: "/v1/chat/completions", userAgent: "codex_cli_rs/0.1", body: []byte(`{"messages":[{"role":"user","content":"chat bypass"}]}`)},
		{path: "/v1/responses?alias=unknown", userAgent: "unknown-client/1", body: []byte(`{"instructions":"unknown UA bypass","model":"e2e"}`)},
	}
	for _, item := range cases {
		headers := http.Header{"Content-Type": []string{"application/json"}, "User-Agent": []string{item.userAgent}}
		response, body, err := s.request(s.dataClient, http.MethodPost, s.guardURL+item.path, item.body, headers)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("bypass request returned status %d", response.StatusCode)
		}
		var echo echoResponse
		if json.Unmarshal(body, &echo) != nil || echo.BodyLength != len(item.body) {
			return errors.New("bypass request body was not preserved")
		}
		digest := sha256.Sum256(item.body)
		if echo.BodySHA256 != hex.EncodeToString(digest[:]) {
			return errors.New("bypass request body hash changed")
		}
	}
	return nil
}

func (s *suite) checkNativeResponses() error {
	response, body, err := s.request(s.dataClient, http.MethodGet, s.guardURL+"/native-error", nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusTeapot || string(body) != "native-teapot" ||
		!reflect.DeepEqual(response.Header.Values("X-E2E-Multi"), []string{"first", "second"}) {
		return errors.New("native upstream error was not preserved")
	}

	response, _, err = s.request(s.dataClient, http.MethodGet, s.guardURL+"/redirect", nil, nil)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusTemporaryRedirect || response.Header.Get("Location") != "/login?from=e2e" ||
		len(response.Cookies()) != 2 {
		return errors.New("redirect or Set-Cookie headers were not preserved")
	}

	headers := http.Header{"Accept-Encoding": []string{"gzip"}}
	response, body, err = s.request(s.dataClient, http.MethodGet, s.guardURL+"/compressed", nil, headers)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "gzip" {
		return errors.New("compressed response headers were not preserved")
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return errors.New("compressed response was invalid")
	}
	plain, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(plain) != "compressed-through-guard" {
		return errors.New("compressed response body changed")
	}
	return nil
}

func (s *suite) checkSSE() error {
	request, err := http.NewRequest(http.MethodGet, s.guardURL+"/sse", nil)
	if err != nil {
		return err
	}
	response, err := s.dataClient.Do(request)
	if err != nil {
		return fmt.Errorf("SSE request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Content-Type"), "text/event-stream") {
		return errors.New("SSE response metadata changed")
	}
	scanner := bufio.NewScanner(response.Body)
	if !scanner.Scan() || scanner.Text() != "data: first" {
		return errors.New("first SSE event was not received")
	}
	firstAt := time.Now()
	if !scanner.Scan() || scanner.Text() != "" {
		return errors.New("first SSE event terminator is invalid")
	}
	if !scanner.Scan() || scanner.Text() != "data: second" {
		return errors.New("second SSE event was not received")
	}
	if time.Since(firstAt) < 450*time.Millisecond {
		return errors.New("SSE response was buffered instead of flushed")
	}
	return nil
}

func (s *suite) login() error {
	payload, _ := json.Marshal(map[string]string{"username": "admin", "password": s.password})
	headers := http.Header{"Content-Type": []string{"application/json"}}
	response, _, err := s.request(s.adminClient, http.MethodPost, s.adminURL+"/api/v1/auth/login", payload, headers)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("admin login returned status %d", response.StatusCode)
	}
	base, _ := url.Parse(s.adminURL + "/")
	for _, cookie := range s.adminClient.Jar.Cookies(base) {
		if cookie.Name == "ncg_csrf" {
			s.csrf = cookie.Value
		}
	}
	if s.csrf == "" {
		return errors.New("admin login did not set the CSRF cookie")
	}
	return nil
}

func (s *suite) checkRiskBlock() error {
	prompt := guardedPrompt()
	digest := sha256.Sum256([]byte(prompt))
	hash := hex.EncodeToString(digest[:])
	payload, _ := json.Marshal(map[string]string{"sha256": hash, "label": "compose E2E rule", "content": prompt})
	response, _, _, err := s.adminJSON(http.MethodPost, "/api/v1/risk-hashes", payload)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusCreated {
		return fmt.Errorf("risk rule creation returned status %d", response.StatusCode)
	}
	response, rulesBody, _, err := s.adminJSON(http.MethodGet, "/api/v1/risk-hashes", nil)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(rulesBody, []byte(prompt)) {
		return errors.New("risk rule API did not expose its stored plaintext to the authenticated admin")
	}
	before, err := s.stats()
	if err != nil {
		return err
	}
	if err := s.expectBlocked(prompt); err != nil {
		return err
	}
	after, err := s.stats()
	if err != nil {
		return err
	}
	if routeCount(before, "POST /v1/responses") != routeCount(after, "POST /v1/responses") {
		return errors.New("blocked request reached the upstream")
	}

	var listing struct {
		Items []event `json:"items"`
	}
	var eventsBody []byte
	for attempt := 0; attempt < 20; attempt++ {
		response, body, _, requestErr := s.adminJSON(http.MethodGet, "/api/v1/events?page=1&page_size=50", nil)
		if requestErr != nil || response.StatusCode != http.StatusOK {
			return errors.New("blocked event could not be read")
		}
		eventsBody = body
		if bytes.Contains(eventsBody, []byte(prompt)) {
			return errors.New("ordinary event API exposed blocked plaintext")
		}
		if json.Unmarshal(eventsBody, &listing) != nil {
			return errors.New("event list returned invalid JSON")
		}
		if hasEventHash(listing.Items, hash) && hasUnreviewedMarkers(listing.Items) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	var blocked event
	for _, item := range listing.Items {
		if item.PromptSHA256 == hash {
			blocked = item
			break
		}
	}
	if blocked.ID == 0 || blocked.Path != "/v1/responses" || blocked.Decision != "block" ||
		blocked.Action != "audit" || blocked.Outcome != "block" || blocked.Reason != "risk_hash_match" ||
		blocked.FieldName != "instructions" || blocked.ClientProfile != "codex_cli" ||
		len(blocked.APIKeyFingerprint) != 64 || blocked.APIKeyHint != "…A7F2" ||
		blocked.UpstreamAccessed || !blocked.EvidenceAvailable {
		return errors.New("blocked event contract is incomplete")
	}
	if bytes.Contains(eventsBody, []byte("e2e-client-secret-A7F2")) {
		return errors.New("ordinary event API exposed a raw request API key")
	}
	response, rulesBody, _, err = s.adminJSON(http.MethodGet, "/api/v1/risk-hashes", nil)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Contains(rulesBody, []byte(`"api_key_hint":"…A7F2"`)) ||
		bytes.Contains(rulesBody, []byte("e2e-client-secret-A7F2")) {
		return errors.New("risk rule did not retain only the masked source-key trace")
	}
	if !hasUnreviewedMarkers(listing.Items) {
		return errors.New("missing unreviewed traffic marker")
	}

	response, evidenceBody, evidenceHeaders, err := s.adminJSON(http.MethodGet, fmt.Sprintf("/api/v1/events/%d/evidence", blocked.ID), nil)
	if err != nil || response.StatusCode != http.StatusOK || evidenceHeaders.Get("Cache-Control") != "no-store" {
		return errors.New("blocked evidence endpoint failed")
	}
	var evidence struct {
		FieldName string `json:"field_name"`
		Content   string `json:"content"`
		Partial   bool   `json:"partial"`
	}
	if json.Unmarshal(evidenceBody, &evidence) != nil || evidence.FieldName != "instructions" ||
		evidence.Content != prompt || evidence.Partial {
		return errors.New("blocked evidence did not preserve exact plaintext")
	}

	response, configBody, _, err := s.adminJSON(http.MethodGet, "/api/v1/config", nil)
	if err != nil || response.StatusCode != http.StatusOK {
		return errors.New("admin config could not be read")
	}
	if bytes.Contains(configBody, []byte(prompt)) || bytes.Contains(configBody, []byte(s.password)) ||
		bytes.Contains(configBody, []byte("e2e-master-key-not-for-production")) {
		return errors.New("admin config API exposed a secret")
	}
	return nil
}

func (s *suite) expectBlocked(prompt string) error {
	payload, _ := json.Marshal(map[string]string{"model": "e2e", "instructions": prompt})
	headers := http.Header{"Content-Type": []string{"application/json"}, "User-Agent": []string{"codex_cli_rs/0.1"}, "Authorization": []string{"Bearer e2e-client-secret-A7F2"}}
	response, body, err := s.request(s.dataClient, http.MethodPost, s.guardURL+"/v1/responses?trace=e2e", payload, headers)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusForbidden || response.Header.Get("Cache-Control") != "no-store" ||
		bytes.Contains(body, []byte(prompt)) {
		return errors.New("risk request was not safely blocked")
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error.Code != "nocyber_guard_blocked" {
		return errors.New("block response does not use the public error envelope")
	}
	return nil
}

func (s *suite) checkAuditedFailOpen() error {
	before, err := s.stats()
	if err != nil {
		return err
	}
	payload := []byte(`{"model":"e2e","instructions":"ordinary compose fail-open prompt"}`)
	headers := http.Header{"Content-Type": []string{"application/json"}, "User-Agent": []string{"codex_cli_rs/0.1"}}
	response, body, err := s.request(s.dataClient, http.MethodPost, s.guardURL+"/v1/responses", payload, headers)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("AI-unavailable fail-open returned status %d", response.StatusCode)
	}
	var echo echoResponse
	if json.Unmarshal(body, &echo) != nil || echo.BodyLength != len(payload) {
		return errors.New("AI-unavailable fail-open changed the request body")
	}
	after, err := s.stats()
	if err != nil {
		return err
	}
	if routeCount(after, "POST /v1/responses") != routeCount(before, "POST /v1/responses")+1 {
		return errors.New("fail-open request did not reach the upstream exactly once")
	}
	time.Sleep(100 * time.Millisecond)
	_, eventsBody, _, err := s.adminJSON(http.MethodGet, "/api/v1/events?page=1&page_size=50", nil)
	if err != nil {
		return err
	}
	if bytes.Contains(eventsBody, []byte("ordinary compose fail-open prompt")) || bytes.Contains(eventsBody, []byte(guardedPrompt())) {
		return errors.New("ordinary event API exposed request plaintext")
	}
	return nil
}

func (s *suite) stats() (upstreamStats, error) {
	response, body, err := s.request(s.dataClient, http.MethodGet, s.upstreamURL+"/__e2e/stats", nil, nil)
	if err != nil {
		return upstreamStats{}, err
	}
	if response.StatusCode != http.StatusOK {
		return upstreamStats{}, errors.New("fake upstream stats endpoint failed")
	}
	var result upstreamStats
	if json.Unmarshal(body, &result) != nil {
		return upstreamStats{}, errors.New("fake upstream stats returned invalid JSON")
	}
	return result, nil
}

func routeCount(value upstreamStats, route string) int { return value.Routes[route] }

func containsEvent(events []event, path, reason string) bool {
	for _, item := range events {
		if item.Path == path && item.Reason == reason && item.Decision == "allow" && item.UpstreamAccessed {
			return true
		}
	}
	return false
}

func hasEventHash(events []event, hash string) bool {
	for _, item := range events {
		if item.PromptSHA256 == hash {
			return true
		}
	}
	return false
}

func hasUnreviewedMarkers(events []event) bool {
	for _, expected := range []struct {
		path   string
		reason string
	}{
		{path: "/ws", reason: "websocket_unreviewed_allow"},
		{path: "/v1/chat/completions", reason: "protocol_unreviewed_allow"},
		{path: "/v1/responses", reason: "ua_bypass"},
	} {
		if !containsEvent(events, expected.path, expected.reason) {
			return false
		}
	}
	return true
}

func (s *suite) adminJSON(method, path string, payload []byte) (*http.Response, []byte, http.Header, error) {
	headers := make(http.Header)
	if payload != nil {
		headers.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions {
		headers.Set("X-CSRF-Token", s.csrf)
	}
	response, body, err := s.request(s.adminClient, method, s.adminURL+path, payload, headers)
	if err != nil {
		return nil, nil, nil, err
	}
	return response, body, response.Header.Clone(), nil
}

func (s *suite) request(client *http.Client, method, endpoint string, payload []byte, headers http.Header) (*http.Response, []byte, error) {
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return nil, nil, err
	}
	return response, body, nil
}

func guardedPrompt() string {
	digest := sha256.Sum256([]byte("nocyber-guard-compose-e2e-v1"))
	return "NCG_E2E_" + strings.ToUpper(hex.EncodeToString(digest[:]))
}

func containsForwardedValue(values []string, forbidden string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.TrimSpace(part) == forbidden {
				return true
			}
		}
	}
	return false
}

func checkWebSocket(base string) error {
	parsed, err := url.Parse(base)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", parsed.Host, 3*time.Second)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	request, _ := http.NewRequest(http.MethodGet, base+"/ws", nil)
	_, _ = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nUser-Agent: codex_cli_rs/0.1\r\n\r\n", parsed.Host, key)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return fmt.Errorf("websocket handshake failed: %w", err)
	}
	acceptDigest := sha1.Sum([]byte(key + websocketGUID))
	wantAccept := base64.StdEncoding.EncodeToString(acceptDigest[:])
	if response.StatusCode != http.StatusSwitchingProtocols || response.Header.Get("Sec-WebSocket-Accept") != wantAccept {
		return errors.New("websocket upgrade response changed")
	}
	if err := writeMaskedFrame(conn, 0x1, []byte("through-guard")); err != nil {
		return err
	}
	opcode, payload, err := readServerFrame(reader)
	if err != nil || opcode != 0x1 || string(payload) != "through-guard" {
		return errors.New("websocket text frame did not round-trip")
	}
	if err := writeMaskedFrame(conn, 0x9, []byte("pulse")); err != nil {
		return err
	}
	opcode, payload, err = readServerFrame(reader)
	if err != nil || opcode != 0xA || string(payload) != "pulse" {
		return errors.New("websocket control frame did not round-trip")
	}
	return writeMaskedFrame(conn, 0x8, nil)
}

func writeMaskedFrame(writer io.Writer, opcode byte, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("test websocket frame is too large")
	}
	mask := make([]byte, 4)
	if _, err := rand.Read(mask); err != nil {
		return err
	}
	frame := []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	frame = append(frame, mask...)
	for index, value := range payload {
		frame = append(frame, value^mask[index%len(mask)])
	}
	_, err := writer.Write(frame)
	return err
}

func readServerFrame(reader *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	if header[1]&0x80 != 0 {
		return 0, nil, errors.New("server websocket frame was masked")
	}
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if length > 64<<10 {
		return 0, nil, errors.New("server websocket frame is too large")
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	return header[0] & 0x0f, payload, nil
}
