package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type auditorFunc func(context.Context, *http.Request, []byte) (Decision, error)

func (f auditorFunc) Evaluate(ctx context.Context, r *http.Request, b []byte) (Decision, error) {
	return f(ctx, r, b)
}

type observation struct {
	method string
	path   string
	reason string
}

type observingAuditor struct {
	evaluate auditorFunc
	mu       sync.Mutex
	seen     []observation
}

func (a *observingAuditor) Evaluate(ctx context.Context, r *http.Request, body []byte) (Decision, error) {
	if a.evaluate == nil {
		return Decision{Allow: true}, nil
	}
	return a.evaluate(ctx, r, body)
}

func (a *observingAuditor) Observe(_ context.Context, r *http.Request, reason string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seen = append(a.seen, observation{method: r.Method, path: r.URL.Path, reason: reason})
}

func (a *observingAuditor) observations() []observation {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]observation(nil), a.seen...)
}

type forcingRouteAuditor struct{ *observingAuditor }

func (*forcingRouteAuditor) ShouldAudit(*http.Request) bool { return true }

type dynamicLimitAuditor struct {
	*observingAuditor
	limit atomic.Int64
}

func (a *dynamicLimitAuditor) AuditBodyLimit(*http.Request) int64 { return a.limit.Load() }

var errSyntheticBodyRead = errors.New("synthetic body read failure")

type syntheticTimeoutError struct{}

func (syntheticTimeoutError) Error() string   { return "synthetic timeout" }
func (syntheticTimeoutError) Timeout() bool   { return true }
func (syntheticTimeoutError) Temporary() bool { return false }

type transientReadErrorBody struct {
	stage  int
	closed atomic.Bool
}

type responseSnapshot struct {
	status  int
	body    []byte
	header  http.Header
	trailer http.Header
}

func (b *transientReadErrorBody) Read(p []byte) (int, error) {
	switch b.stage {
	case 0:
		b.stage++
		return copy(p, "prefix-"), errSyntheticBodyRead
	case 1:
		b.stage++
		return copy(p, "suffix"), nil
	default:
		return 0, io.EOF
	}
}

func (b *transientReadErrorBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestProtectedPathsAreExact(t *testing.T) {
	yes := []string{"/v1/responses", "/responses", "/backend-api/codex/responses"}
	for _, p := range yes {
		if !ProtectedPath(p) {
			t.Errorf("expected protected: %s", p)
		}
	}
	no := []string{"/v1/responses/", "/responses/compact", "/v1/chat/completions", "/responses/foo"}
	for _, p := range no {
		if ProtectedPath(p) {
			t.Errorf("must bypass: %s", p)
		}
	}
}

func TestProxyPreservesRawRequestAndResponse(t *testing.T) {
	body := []byte("{\"instructions\":\"  x \\u4e2d  \"}")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("body changed: %q", got)
		}
		if r.URL.EscapedPath() != "/v1/responses" || r.URL.RawQuery != "x=1;x=2&escaped=%2f&x=3" {
			t.Errorf("url changed: %s", r.URL.String())
		}
		if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Cookie") != "a=1; b=2" {
			t.Error("end-to-end headers changed")
		}
		if r.Header.Get("X-Remove-Me") != "" {
			t.Error("Connection-nominated request header reached upstream")
		}
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		w.Header().Set("Location", "/login?next=%2Fadmin")
		w.Header().Set("Connection", "X-Remove-Upstream")
		w.Header().Set("X-Remove-Upstream", "not-end-to-end")
		w.Header().Add("Trailer", "X-Body-Checksum")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("raw-response"))
		w.Header().Set("X-Body-Checksum", "sha256:example")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var audited []byte
	h := (&Server{Upstream: u, MaxBody: 64, Auditor: auditorFunc(func(_ context.Context, _ *http.Request, b []byte) (Decision, error) {
		audited = append([]byte(nil), b...)
		return Decision{Allow: true}, nil
	})}).Handler()
	req := httptest.NewRequest(http.MethodPost, "http://guard/v1/responses?x=1;x=2&escaped=%2f&x=3", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Cookie", "a=1; b=2")
	req.Header.Set("Connection", "keep-alive, X-Remove-Me")
	req.Header.Set("X-Remove-Me", "not-end-to-end")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !bytes.Equal(audited, body) {
		t.Fatal("auditor did not receive exact bytes")
	}
	if rr.Code != http.StatusCreated || rr.Body.String() != "raw-response" {
		t.Fatalf("response changed: %d %q", rr.Code, rr.Body.String())
	}
	if len(rr.Result().Cookies()) != 2 {
		t.Fatalf("Set-Cookie lost: %v", rr.Header())
	}
	if got := rr.Header().Get("Location"); got != "/login?next=%2Fadmin" {
		t.Fatalf("Location changed: %q", got)
	}
	if rr.Header().Get("X-Remove-Upstream") != "" {
		t.Error("Connection-nominated response header reached client")
	}
	if rr.Result().Trailer.Get("X-Body-Checksum") != "sha256:example" {
		t.Fatalf("response trailer lost: %v", rr.Result().Trailer)
	}
}

func TestWebLoginAndCORSMatchDirectUpstream(t *testing.T) {
	var callsMu sync.Mutex
	calls := make(map[string]int)
	validationErrors := make(chan error, 8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		calls[r.Header.Get("X-Test-Request")]++
		callsMu.Unlock()

		w.Header().Add("X-Multi-Value", "first")
		w.Header().Add("X-Multi-Value", "second")
		switch r.URL.Path {
		case "/":
			if r.Method != http.MethodGet || r.URL.RawQuery != "view=full&encoded=%2Fdocs" {
				validationErrors <- fmt.Errorf("web request changed: method=%s uri=%s", r.Method, r.URL.RequestURI())
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Add("Trailer", "X-Upstream-Digest")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "<!doctype html><title>NoCyber test</title>")
			w.Header().Set("X-Upstream-Digest", "sha256:web")
		case "/login":
			requestID := r.Header.Get("X-Test-Request")
			body, err := io.ReadAll(r.Body)
			if err != nil {
				validationErrors <- fmt.Errorf("read login body for %s: %w", requestID, err)
			}
			if r.Method != http.MethodPost || r.URL.RawQuery != "next=%2Fconsole&repeat=1&repeat=2" || string(body) != "username=abin&password=space" {
				validationErrors <- fmt.Errorf("login request changed: method=%s uri=%s body=%q", r.Method, r.URL.RequestURI(), body)
			}
			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Origin") != "https://console.example" || r.Header.Get("Cookie") != "session=old; theme=dark" {
				validationErrors <- fmt.Errorf("login headers changed: %v", r.Header)
			}
			if !equalStringSlices(r.Header.Values("X-Request-Tag"), []string{"one", "two"}) {
				validationErrors <- fmt.Errorf("login multi-value request header changed: %v", r.Header.Values("X-Request-Tag"))
			}
			if r.Trailer.Get("X-Request-Digest") != "sha256:login" {
				validationErrors <- fmt.Errorf("login request trailer for %s changed: %v", requestID, r.Trailer)
			}
			w.Header().Add("Set-Cookie", "session=new; Path=/; HttpOnly; SameSite=Lax")
			w.Header().Add("Set-Cookie", "csrf=token; Path=/; SameSite=Strict")
			w.Header().Set("Location", "/console?from=login&encoded=%2F")
			w.WriteHeader(http.StatusSeeOther)
			_, _ = io.WriteString(w, "redirecting")
		case "/api/session":
			if r.Method != http.MethodOptions || r.Header.Get("Origin") != "https://console.example" || r.Header.Get("Access-Control-Request-Method") != http.MethodPost {
				validationErrors <- fmt.Errorf("CORS preflight changed: method=%s headers=%v", r.Method, r.Header)
			}
			w.Header().Set("Access-Control-Allow-Origin", "https://console.example")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Access-Control-Expose-Headers", "X-Request-ID")
			w.Header().Add("Access-Control-Expose-Headers", "X-RateLimit-Remaining")
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.WriteHeader(http.StatusNoContent)
		default:
			validationErrors <- fmt.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	var audits atomic.Int64
	guard := httptest.NewServer((&Server{Upstream: upstreamURL, Auditor: auditorFunc(func(context.Context, *http.Request, []byte) (Decision, error) {
		audits.Add(1)
		return Decision{Blocked: true}, nil
	})}).Handler())
	defer guard.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	tests := []struct {
		name    string
		method  string
		path    string
		body    string
		headers http.Header
		trailer http.Header
		compare []string
	}{
		{
			name: "web page", method: http.MethodGet, path: "/?view=full&encoded=%2Fdocs",
			compare: []string{"Content-Type", "X-Multi-Value"},
		},
		{
			name: "login", method: http.MethodPost, path: "/login?next=%2Fconsole&repeat=1&repeat=2", body: "username=abin&password=space",
			headers: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}, "Origin": {"https://console.example"}, "Cookie": {"session=old; theme=dark"}, "X-Request-Tag": {"one", "two"}},
			trailer: http.Header{"X-Request-Digest": {"sha256:login"}},
			compare: []string{"Location", "Set-Cookie", "X-Multi-Value"},
		},
		{
			name: "CORS preflight", method: http.MethodOptions, path: "/api/session",
			headers: http.Header{"Origin": {"https://console.example"}, "Access-Control-Request-Method": {http.MethodPost}, "Access-Control-Request-Headers": {"Authorization, Content-Type"}},
			compare: []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers", "Vary", "X-Multi-Value"},
		},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			directID := fmt.Sprintf("direct-%d", index)
			guardID := fmt.Sprintf("guard-%d", index)
			direct := doSnapshot(t, client, tc.method, upstream.URL+tc.path, tc.body, tc.headers, tc.trailer, directID)
			proxied := doSnapshot(t, client, tc.method, guard.URL+tc.path, tc.body, tc.headers, tc.trailer, guardID)
			assertResponseMatches(t, direct, proxied, tc.compare...)
			callsMu.Lock()
			gotCalls := calls[guardID]
			callsMu.Unlock()
			if gotCalls != 1 {
				t.Fatalf("proxy reached upstream %d times, want exactly once", gotCalls)
			}
		})
	}
	close(validationErrors)
	for err := range validationErrors {
		t.Error(err)
	}
	if got := audits.Load(); got != 0 {
		t.Fatalf("unprotected browser requests were audited %d times", got)
	}
}

func TestBypassDoesNotReadBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	called := false
	h := (&Server{Upstream: u, Auditor: auditorFunc(func(context.Context, *http.Request, []byte) (Decision, error) { called = true; return Decision{}, nil })}).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "http://guard/responses/compact", strings.NewReader("opaque")))
	if called || rr.Body.String() != "opaque" {
		t.Fatalf("bypass was altered called=%v body=%q", called, rr.Body.String())
	}
}

func TestOversizeAuditBodyIsReplayedCompletely(t *testing.T) {
	body := []byte(strings.Repeat("0123456789", 32))
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("oversize body changed: got %d bytes, want %d", len(got), len(body))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	auditor := &observingAuditor{evaluate: func(context.Context, *http.Request, []byte) (Decision, error) {
		evaluations.Add(1)
		return Decision{Allow: true}, nil
	}}
	h := (&Server{Upstream: u, MaxBody: 31, Auditor: auditor}).Handler()
	req := httptest.NewRequest(http.MethodPost, "http://guard/v1/responses", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || upstreamCalls.Load() != 1 {
		t.Fatalf("request was not forwarded exactly once: status=%d calls=%d", rr.Code, upstreamCalls.Load())
	}
	if evaluations.Load() != 0 {
		t.Fatalf("oversize request was evaluated %d times", evaluations.Load())
	}
	seen := auditor.observations()
	if len(seen) != 1 || seen[0].reason != "oversize_bypass" {
		t.Fatalf("unexpected observations: %+v", seen)
	}
}

func TestBodyReadFailureReplaysBytesAlreadyConsumed(t *testing.T) {
	const want = "prefix-suffix"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read replayed body: %v", err)
		}
		if string(got) != want {
			t.Errorf("replayed body=%q, want %q", got, want)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	auditor := &observingAuditor{evaluate: func(context.Context, *http.Request, []byte) (Decision, error) {
		evaluations.Add(1)
		return Decision{Blocked: true}, nil
	}}
	body := &transientReadErrorBody{}
	req := httptest.NewRequest(http.MethodPost, "http://guard/v1/responses", nil)
	req.Body = body
	req.ContentLength = -1
	rr := httptest.NewRecorder()
	(&Server{Upstream: u, MaxBody: 1024, Auditor: auditor}).Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	if evaluations.Load() != 0 {
		t.Fatalf("request with read error was evaluated %d times", evaluations.Load())
	}
	seen := auditor.observations()
	if len(seen) != 1 || seen[0].reason != "body_read_fail_open" {
		t.Fatalf("unexpected observations: %+v", seen)
	}
	if err := req.Body.Close(); err != nil {
		t.Fatalf("close replay body: %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("original request body was not closed")
	}
}

func TestBodyLimitProviderIsReadForEveryRequest(t *testing.T) {
	body := []byte(`{"instructions":"dynamic"}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		_, _ = w.Write(got)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	auditor := &dynamicLimitAuditor{observingAuditor: &observingAuditor{evaluate: func(_ context.Context, _ *http.Request, got []byte) (Decision, error) {
		evaluations.Add(1)
		if !bytes.Equal(got, body) {
			t.Errorf("audited body changed: %q", got)
		}
		return Decision{Allow: true}, nil
	}}}
	auditor.limit.Store(8)
	h := (&Server{Upstream: u, MaxBody: 4, Auditor: auditor}).Handler()
	for i, limit := range []int64{8, 128} {
		auditor.limit.Store(limit)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "http://guard/v1/responses", bytes.NewReader(body)))
		if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), body) {
			t.Fatalf("request %d changed: status=%d body=%q", i, rr.Code, rr.Body.Bytes())
		}
	}
	if evaluations.Load() != 1 {
		t.Fatalf("evaluations=%d, want only second request evaluated", evaluations.Load())
	}
	seen := auditor.observations()
	if len(seen) != 1 || seen[0].reason != "oversize_bypass" {
		t.Fatalf("unexpected observations: %+v", seen)
	}
}

func TestGzipAuditUsesDecodedCopyAndForwardsOriginal(t *testing.T) {
	plain := []byte(`{"instructions":"compressed"}`)
	compressed := gzipPayload(t, plain)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, compressed) {
			t.Errorf("compressed body changed in transit")
		}
		if r.Header.Get("Content-Encoding") != "gzip" || r.ContentLength != int64(len(compressed)) {
			t.Errorf("compression metadata changed: encoding=%q length=%d", r.Header.Get("Content-Encoding"), r.ContentLength)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{Upstream: u, MaxBody: 1024, Auditor: auditorFunc(func(_ context.Context, _ *http.Request, got []byte) (Decision, error) {
		if !bytes.Equal(got, plain) {
			t.Errorf("audit copy was not decoded: %q", got)
		}
		return Decision{Allow: true}, nil
	})}).Handler()
	req := httptest.NewRequest(http.MethodPost, "http://guard/v1/responses", bytes.NewReader(compressed))
	req.Header.Set("Content-Encoding", "gzip")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestUnknownAndInvalidContentEncodingFailOpen(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		body     []byte
		reason   string
	}{
		{name: "unknown", encoding: "br", body: []byte("opaque-brotli-bytes"), reason: "unsupported_content_encoding_fail_open"},
		{name: "invalid gzip", encoding: "gzip", body: []byte("not-a-gzip-stream"), reason: "content_decode_fail_open"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				got, _ := io.ReadAll(r.Body)
				if !bytes.Equal(got, tc.body) || r.Header.Get("Content-Encoding") != tc.encoding {
					t.Errorf("encoded request changed: encoding=%q body=%q", r.Header.Get("Content-Encoding"), got)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			u, _ := url.Parse(upstream.URL)
			var evaluations atomic.Int64
			auditor := &observingAuditor{evaluate: func(context.Context, *http.Request, []byte) (Decision, error) {
				evaluations.Add(1)
				return Decision{Blocked: true}, nil
			}}
			h := (&Server{Upstream: u, MaxBody: 1024, Auditor: auditor}).Handler()
			req := httptest.NewRequest(http.MethodPost, "http://guard/v1/responses", bytes.NewReader(tc.body))
			req.Header.Set("Content-Encoding", tc.encoding)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusNoContent || upstreamCalls.Load() != 1 || evaluations.Load() != 0 {
				t.Fatalf("not fail-open: status=%d upstream=%d evaluations=%d", rr.Code, upstreamCalls.Load(), evaluations.Load())
			}
			seen := auditor.observations()
			if len(seen) != 1 || seen[0].reason != tc.reason {
				t.Fatalf("unexpected observations: %+v", seen)
			}
		})
	}
}

func TestEncodedResponsesMatchDirectUpstream(t *testing.T) {
	gzipBody := gzipPayload(t, []byte(`{"result":"compressed"}`))
	tests := []struct {
		name     string
		encoding string
		body     []byte
	}{
		{name: "gzip", encoding: "gzip", body: gzipBody},
		{name: "unknown", encoding: "br", body: []byte("opaque-brotli-response")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int64
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", tc.encoding)
				w.Header().Add("X-Upstream-Value", "one")
				w.Header().Add("X-Upstream-Value", "two")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(tc.body)
			}))
			defer upstream.Close()
			upstreamURL, _ := url.Parse(upstream.URL)
			guard := httptest.NewServer((&Server{Upstream: upstreamURL}).Handler())
			defer guard.Close()

			client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
			direct := doSnapshot(t, client, http.MethodGet, upstream.URL+"/encoded", "", nil, nil, "direct")
			proxied := doSnapshot(t, client, http.MethodGet, guard.URL+"/encoded", "", nil, nil, "guard")
			assertResponseMatches(t, direct, proxied, "Content-Type", "Content-Encoding", "Content-Length", "X-Upstream-Value")
			if !bytes.Equal(proxied.body, tc.body) {
				t.Fatalf("encoded response body changed: got %x want %x", proxied.body, tc.body)
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("upstream calls=%d, want one direct and one proxied call", got)
			}
		})
	}
}

func TestNativeErrorResponsesMatchDirectUpstream(t *testing.T) {
	tests := []struct {
		path   string
		status int
		body   string
	}{
		{path: "/invalid", status: http.StatusUnprocessableEntity, body: `{"error":"invalid upstream request"}`},
		{path: "/unavailable", status: http.StatusServiceUnavailable, body: "upstream temporarily unavailable\n"},
	}
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		for _, tc := range tests {
			if r.URL.Path == tc.path {
				w.Header().Set("Content-Type", "application/problem+json")
				w.Header().Set("Retry-After", "17")
				w.Header().Add("WWW-Authenticate", `Bearer realm="primary"`)
				w.Header().Add("WWW-Authenticate", `Basic realm="fallback"`)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	guard := httptest.NewServer((&Server{Upstream: upstreamURL}).Handler())
	defer guard.Close()

	client := &http.Client{}
	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			direct := doSnapshot(t, client, http.MethodGet, upstream.URL+tc.path, "", nil, nil, "direct-"+tc.path)
			proxied := doSnapshot(t, client, http.MethodGet, guard.URL+tc.path, "", nil, nil, "guard-"+tc.path)
			assertResponseMatches(t, direct, proxied, "Content-Type", "Content-Length", "Retry-After", "WWW-Authenticate")
			if proxied.status != tc.status || string(proxied.body) != tc.body {
				t.Fatalf("native error changed: status=%d body=%q", proxied.status, proxied.body)
			}
		})
	}
	if got, want := calls.Load(), int64(len(tests)*2); got != want {
		t.Fatalf("upstream calls=%d, want %d", got, want)
	}
}

func TestUnsupportedProtocolsAreObservedAndForwarded(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(w, r.Body)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	auditor := &observingAuditor{evaluate: func(context.Context, *http.Request, []byte) (Decision, error) {
		evaluations.Add(1)
		return Decision{Blocked: true}, nil
	}}
	h := (&Server{Upstream: u, Auditor: auditor}).Handler()
	paths := []string{
		"/v1/chat/completions",
		"/v1/messages",
		"/v1beta/models/gemini:generateContent",
		"/v1beta/models/gemini:streamGenerateContent",
	}
	for _, path := range paths {
		body := []byte("opaque:" + path)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "http://guard"+path, bytes.NewReader(body)))
		if rr.Code != http.StatusOK || !bytes.Equal(rr.Body.Bytes(), body) {
			t.Fatalf("path %s changed: status=%d body=%q", path, rr.Code, rr.Body.Bytes())
		}
	}
	if evaluations.Load() != 0 || upstreamCalls.Load() != int64(len(paths)) {
		t.Fatalf("evaluations=%d upstream=%d", evaluations.Load(), upstreamCalls.Load())
	}
	seen := auditor.observations()
	if len(seen) != len(paths) {
		t.Fatalf("observations=%+v", seen)
	}
	for i, event := range seen {
		if event.path != paths[i] || event.method != http.MethodPost || event.reason != "protocol_unreviewed_allow" {
			t.Errorf("observation %d = %+v", i, event)
		}
	}
}

func TestWebSocketUpgradeAndControlFramesAreTransparent(t *testing.T) {
	upstreamDone := make(chan error, 1)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		upstreamDone <- func() error {
			if r.URL.Path != "/v1/responses" || r.URL.RawQuery != "mode=ws" {
				return fmt.Errorf("websocket URL changed: %s", r.URL.String())
			}
			if r.Header.Get("Authorization") != "Bearer websocket-secret" || !isWebSocket(r) {
				return fmt.Errorf("websocket headers changed: %v", r.Header)
			}
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				return fmt.Errorf("upstream response writer cannot hijack")
			}
			conn, stream, err := hijacker.Hijack()
			if err != nil {
				return err
			}
			defer conn.Close()
			accept := websocketAccept(r.Header.Get("Sec-WebSocket-Key"))
			if _, err := fmt.Fprintf(stream, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept); err != nil {
				return err
			}
			if err := stream.Flush(); err != nil {
				return err
			}
			opcode, payload, err := readWebSocketFrame(stream.Reader)
			if err != nil {
				return err
			}
			if opcode != 0x9 || string(payload) != "are-you-there" {
				return fmt.Errorf("unexpected first frame opcode=%d payload=%q", opcode, payload)
			}
			if err := writeWebSocketFrame(stream, 0xa, payload, false); err != nil {
				return err
			}
			if err := stream.Flush(); err != nil {
				return err
			}
			opcode, payload, err = readWebSocketFrame(stream.Reader)
			if err != nil {
				return err
			}
			if opcode != 0x1 || string(payload) != "client-to-upstream" {
				return fmt.Errorf("unexpected data frame opcode=%d payload=%q", opcode, payload)
			}
			if err := writeWebSocketFrame(stream, 0x1, []byte("upstream-to-client"), false); err != nil {
				return err
			}
			if err := stream.Flush(); err != nil {
				return err
			}
			if err := writeWebSocketFrame(stream, 0x8, []byte{0x03, 0xe8}, false); err != nil {
				return err
			}
			return stream.Flush()
		}()
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	baseAuditor := &observingAuditor{evaluate: func(context.Context, *http.Request, []byte) (Decision, error) {
		evaluations.Add(1)
		return Decision{Blocked: true}, nil
	}}
	auditor := &forcingRouteAuditor{observingAuditor: baseAuditor}
	guard := httptest.NewServer((&Server{Upstream: u, Auditor: auditor}).Handler())
	defer guard.Close()

	guardURL, _ := url.Parse(guard.URL)
	conn, err := net.DialTimeout("tcp", guardURL.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	const key = "dGhlIHNhbXBsZSBub25jZQ=="
	if _, err := fmt.Fprintf(conn, "GET /v1/responses?mode=ws HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nAuthorization: Bearer websocket-secret\r\n\r\n", guardURL.Host, key); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, " 101 ") || !strings.EqualFold(headers.Get("Upgrade"), "websocket") {
		t.Fatalf("upgrade failed: %q headers=%v", statusLine, headers)
	}
	if headers.Get("Sec-WebSocket-Accept") != websocketAccept(key) {
		t.Fatalf("Sec-WebSocket-Accept=%q", headers.Get("Sec-WebSocket-Accept"))
	}

	if err := writeWebSocketFrame(conn, 0x9, []byte("are-you-there"), true); err != nil {
		t.Fatal(err)
	}
	opcode, payload, err := readWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0xa || string(payload) != "are-you-there" {
		t.Fatalf("pong changed: opcode=%d payload=%q", opcode, payload)
	}
	if err := writeWebSocketFrame(conn, 0x1, []byte("client-to-upstream"), true); err != nil {
		t.Fatal(err)
	}
	opcode, payload, err = readWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x1 || string(payload) != "upstream-to-client" {
		t.Fatalf("data frame changed: opcode=%d payload=%q", opcode, payload)
	}
	opcode, payload, err = readWebSocketFrame(reader)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x8 || !bytes.Equal(payload, []byte{0x03, 0xe8}) {
		t.Fatalf("close frame changed: opcode=%d payload=%x", opcode, payload)
	}

	select {
	case err := <-upstreamDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream websocket handler did not finish")
	}
	if evaluations.Load() != 0 {
		t.Fatalf("websocket request was audited %d times", evaluations.Load())
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("websocket reached upstream %d times", upstreamCalls.Load())
	}
	seen := baseAuditor.observations()
	if len(seen) != 1 || seen[0].reason != "websocket_unreviewed_allow" || seen[0].path != "/v1/responses" {
		t.Fatalf("unexpected observations: %+v", seen)
	}
}

func TestUpstreamNetworkErrorUsesJSONEnvelope(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamURL, _ := url.Parse("http://" + listener.Addr().String())
	_ = listener.Close()
	rr := httptest.NewRecorder()
	(&Server{Upstream: upstreamURL}).Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://guard/status", nil))
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q", got)
	}
	var envelope map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("invalid JSON response: %v: %q", err, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code":"upstream_unavailable"`) {
		t.Fatalf("wrong error envelope: %s", rr.Body.String())
	}
}

func TestUpstreamTimeoutUsesGatewayTimeoutEnvelope(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "context deadline", err: fmt.Errorf("transport: %w", context.DeadlineExceeded)},
		{name: "network timeout", err: fmt.Errorf("transport: %w", syntheticTimeoutError{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			writeUpstreamError(rr, httptest.NewRequest(http.MethodGet, "http://guard/status", nil), tc.err)
			if rr.Code != http.StatusGatewayTimeout || rr.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("status=%d headers=%v", rr.Code, rr.Header())
			}
			if !strings.Contains(rr.Body.String(), `"code":"upstream_timeout"`) {
				t.Fatalf("wrong timeout envelope: %s", rr.Body.String())
			}
		})
	}
}

func TestClientCancellationDoesNotWriteProxyError(t *testing.T) {
	tests := []struct {
		name          string
		cancelRequest bool
		err           error
	}{
		{name: "transport cancellation", err: context.Canceled},
		{name: "request cancellation", cancelRequest: true, err: errors.New("transport stopped")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tc.cancelRequest {
				cancel()
			} else {
				defer cancel()
			}
			req := httptest.NewRequest(http.MethodGet, "http://guard/status", nil).WithContext(ctx)
			rr := httptest.NewRecorder()
			writeUpstreamError(rr, req, tc.err)
			if rr.Body.Len() != 0 || len(rr.Header()) != 0 {
				t.Fatalf("canceled request received proxy response: headers=%v body=%q", rr.Header(), rr.Body.String())
			}
		})
	}
}

func TestClientCancellationPropagatesThroughProxy(t *testing.T) {
	upstreamStarted := make(chan struct{})
	upstreamCanceled := make(chan struct{})
	var upstreamCalls atomic.Int64
	var startedOnce sync.Once
	var canceledOnce sync.Once
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: started\n\n")
		w.(http.Flusher).Flush()
		startedOnce.Do(func() { close(upstreamStarted) })
		<-r.Context().Done()
		canceledOnce.Do(func() { close(upstreamCanceled) })
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	guard := httptest.NewServer((&Server{Upstream: upstreamURL, Auditor: auditorFunc(func(context.Context, *http.Request, []byte) (Decision, error) {
		evaluations.Add(1)
		return Decision{Allow: true}, nil
	})}).Handler())
	defer guard.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, guard.URL+"/v1/responses", strings.NewReader(`{"instructions":"cancel after forward"}`))
	if err != nil {
		t.Fatal(err)
	}
	type requestResult struct {
		response *http.Response
		err      error
	}
	requestDone := make(chan requestResult, 1)
	go func() {
		res, err := http.DefaultClient.Do(req)
		requestDone <- requestResult{response: res, err: err}
	}()

	select {
	case <-upstreamStarted:
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("request never reached upstream")
	}
	var res *http.Response
	select {
	case result := <-requestDone:
		if result.err != nil {
			cancel()
			t.Fatalf("start streaming response: %v", result.err)
		}
		res = result.response
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("canceled client request did not return")
	}
	cancel()
	defer res.Body.Close()
	select {
	case <-upstreamCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not reach upstream request context")
	}
	if upstreamCalls.Load() != 1 || evaluations.Load() != 1 {
		t.Fatalf("upstream calls=%d evaluations=%d, want exactly one each", upstreamCalls.Load(), evaluations.Load())
	}
}

func TestTrustedTLSProxyPreservesForwardingMetadata(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{
		Upstream: u,
		TrustedProxy: func(ip net.IP) bool {
			return ip.IsLoopback() || ip.Equal(net.ParseIP("10.0.0.12"))
		},
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://guard.internal/status", nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.8, 10.0.0.12")
	req.Header.Set("X-Forwarded-Host", "api.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "443")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	headers := <-received
	for name, want := range map[string]string{
		"X-Forwarded-For":   "198.51.100.8, 10.0.0.12, 127.0.0.1",
		"X-Forwarded-Host":  "api.example.com",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Port":  "443",
	} {
		if got := headers.Get(name); got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
}

func TestTrustedProxyDropsSpoofedForwardingPrefixAndInvalidMetadata(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{
		Upstream: u,
		TrustedProxy: func(ip net.IP) bool {
			return ip.IsLoopback() || ip.Equal(net.ParseIP("10.0.0.12"))
		},
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://guard.internal:8088/status", nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("X-Forwarded-For", "192.0.2.44, invalid-hop, 10.0.0.12")
	req.Header.Set("X-Forwarded-Host", "attacker.example/path")
	req.Header.Set("X-Forwarded-Proto", "javascript")
	req.Header.Set("X-Forwarded-Port", "70000")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	headers := <-received
	for name, want := range map[string]string{
		"X-Forwarded-For":   "10.0.0.12, 127.0.0.1",
		"X-Forwarded-Host":  "guard.internal:8088",
		"X-Forwarded-Proto": "http",
		"X-Forwarded-Port":  "8088",
	} {
		if got := headers.Get(name); got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
}

func TestTrustedForwardedForStopsAtFirstUntrustedHop(t *testing.T) {
	trusted := func(ip net.IP) bool { return ip.Equal(net.ParseIP("10.0.0.12")) }
	got := trustedForwardedFor([]string{"192.0.2.44, 198.51.100.8", "10.0.0.12"}, trusted)
	want := []string{"198.51.100.8", "10.0.0.12"}
	if !equalStringSlices(got, want) {
		t.Fatalf("sanitized chain=%q, want %q", got, want)
	}
}

func TestTrustedProxyRejectsAmbiguousForwardingMetadata(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{Upstream: u, TrustedProxy: func(ip net.IP) bool { return ip.IsLoopback() }}).Handler()

	req := httptest.NewRequest(http.MethodGet, "https://guard.internal/status", nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Add("X-Forwarded-Host", "first.example")
	req.Header.Add("X-Forwarded-Host", "second.example")
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.Header.Set("X-Forwarded-Port", "+443")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	headers := <-received
	for name, want := range map[string]string{
		"X-Forwarded-For":   "127.0.0.1",
		"X-Forwarded-Host":  "guard.internal",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Port":  "443",
	} {
		if got := headers.Get(name); got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
}

func TestUntrustedClientCannotSpoofForwardingMetadata(t *testing.T) {
	received := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{
		Upstream: u,
		TrustedProxy: func(ip net.IP) bool {
			return ip.IsLoopback()
		},
	}).Handler()

	req := httptest.NewRequest(http.MethodGet, "http://public.example.com:8088/status", nil)
	req.RemoteAddr = "198.51.100.22:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Port", "443")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rr.Code, rr.Body.String())
	}
	headers := <-received
	for name, want := range map[string]string{
		"X-Forwarded-For":   "198.51.100.22",
		"X-Forwarded-Host":  "public.example.com:8088",
		"X-Forwarded-Proto": "http",
		"X-Forwarded-Port":  "8088",
	} {
		if got := headers.Get(name); got != want {
			t.Errorf("%s=%q, want %q", name, got, want)
		}
	}
}

func websocketAccept(key string) string {
	digest := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(digest[:])
}

func readWebSocketFrame(reader *bufio.Reader) (byte, []byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	length := uint64(second & 0x7f)
	switch length {
	case 126:
		var raw [2]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(raw[:]))
	case 127:
		var raw [8]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(raw[:])
	}
	if length > 1<<20 {
		return 0, nil, fmt.Errorf("test websocket frame too large: %d", length)
	}
	var mask [4]byte
	masked := second&0x80 != 0
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%len(mask)]
		}
	}
	return first & 0x0f, payload, nil
}

func writeWebSocketFrame(writer io.Writer, opcode byte, payload []byte, masked bool) error {
	header := []byte{0x80 | (opcode & 0x0f)}
	maskBit := byte(0)
	if masked {
		maskBit = 0x80
	}
	switch length := len(payload); {
	case length < 126:
		header = append(header, maskBit|byte(length))
	case length <= 65535:
		header = append(header, maskBit|126, 0, 0)
		binary.BigEndian.PutUint16(header[len(header)-2:], uint16(length))
	default:
		header = append(header, maskBit|127, 0, 0, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint64(header[len(header)-8:], uint64(length))
	}
	encoded := payload
	if masked {
		mask := [4]byte{0x11, 0x22, 0x33, 0x44}
		header = append(header, mask[:]...)
		encoded = append([]byte(nil), payload...)
		for i := range encoded {
			encoded[i] ^= mask[i%len(mask)]
		}
	}
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err := writer.Write(encoded)
	return err
}

func gzipPayload(t *testing.T, plain []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func doSnapshot(t *testing.T, client *http.Client, method, target, body string, headers, trailer http.Header, requestID string) responseSnapshot {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if requestID != "" {
		req.Header.Set("X-Test-Request", requestID)
	}
	if len(trailer) > 0 {
		req.Trailer = trailer.Clone()
		req.ContentLength = -1
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return responseSnapshot{status: res.StatusCode, body: responseBody, header: res.Header.Clone(), trailer: res.Trailer.Clone()}
}

func assertResponseMatches(t *testing.T, direct, proxied responseSnapshot, headerNames ...string) {
	t.Helper()
	if proxied.status != direct.status || !bytes.Equal(proxied.body, direct.body) {
		t.Fatalf("response changed: direct=(%d %q) proxied=(%d %q)", direct.status, direct.body, proxied.status, proxied.body)
	}
	for _, name := range headerNames {
		if !equalStringSlices(proxied.header.Values(name), direct.header.Values(name)) {
			t.Errorf("%s changed: direct=%q proxied=%q", name, direct.header.Values(name), proxied.header.Values(name))
		}
	}
	for name, directValues := range direct.trailer {
		if !equalStringSlices(proxied.trailer.Values(name), directValues) {
			t.Errorf("trailer %s changed: direct=%q proxied=%q", name, directValues, proxied.trailer.Values(name))
		}
	}
	for name, proxiedValues := range proxied.trailer {
		if _, exists := direct.trailer[name]; !exists {
			t.Errorf("proxy added trailer %s=%q", name, proxiedValues)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func TestAllowedProtectedRequestCallsUpstreamExactlyOnce(t *testing.T) {
	body := []byte(`{"instructions":"forward exactly once"}`)
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("body changed: got %q want %q", got, body)
		}
		if r.URL.EscapedPath() != "/v1/%72esponses" || r.URL.RawQuery != "model=a%2Fb&stream=true" {
			t.Errorf("request target changed: escaped_path=%q raw_query=%q", r.URL.EscapedPath(), r.URL.RawQuery)
		}
		if r.Trailer.Get("X-Request-Digest") != "sha256:protected" {
			t.Errorf("request trailer changed: %v", r.Trailer)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)
	var evaluations atomic.Int64
	guard := httptest.NewServer((&Server{Upstream: upstreamURL, Auditor: auditorFunc(func(_ context.Context, _ *http.Request, got []byte) (Decision, error) {
		evaluations.Add(1)
		if !bytes.Equal(got, body) {
			t.Errorf("audit body changed: got %q want %q", got, body)
		}
		return Decision{Allow: true}, nil
	})}).Handler())
	defer guard.Close()
	req, err := http.NewRequest(http.MethodPost, guard.URL+"/v1/%72esponses?model=a%2Fb&stream=true", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Trailer = http.Header{"X-Request-Digest": {"sha256:protected"}}
	req.ContentLength = -1
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusAccepted || upstreamCalls.Load() != 1 || evaluations.Load() != 1 {
		t.Fatalf("status=%d upstream=%d evaluations=%d, want 202 and exactly one each", res.StatusCode, upstreamCalls.Load(), evaluations.Load())
	}
}

func TestBlockedNeverCallsUpstream(t *testing.T) {
	var calls atomic.Int64
	var evaluations atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{Upstream: u, Auditor: auditorFunc(func(context.Context, *http.Request, []byte) (Decision, error) {
		evaluations.Add(1)
		return Decision{Blocked: true, Reason: "risk_hash"}, nil
	})}).Handler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "http://guard/v1/responses", strings.NewReader(`{"instructions":"x"}`)))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "nocyber_guard_blocked") {
		t.Fatalf("unexpected block: %d %s", rr.Code, rr.Body.String())
	}
	if calls.Load() != 0 {
		t.Fatalf("upstream called %d times", calls.Load())
	}
	if evaluations.Load() != 1 {
		t.Fatalf("request was evaluated %d times", evaluations.Load())
	}
	if rr.Header().Get("Content-Type") != "application/json" || rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("block response headers=%v", rr.Header())
	}
}

func TestSSEFlushesImmediately(t *testing.T) {
	allowSecondEvent := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(allowSecondEvent) }) }
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-allowSecondEvent
		_, _ = fmt.Fprint(w, "data: second\n\n")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	guard := httptest.NewServer((&Server{Upstream: u}).Handler())
	defer guard.Close()
	defer release()
	type responseResult struct {
		response *http.Response
		err      error
	}
	responseReady := make(chan responseResult, 1)
	go func() {
		res, err := http.Get(guard.URL + "/events")
		responseReady <- responseResult{response: res, err: err}
	}()
	var res *http.Response
	select {
	case result := <-responseReady:
		if result.err != nil {
			t.Fatal(result.err)
		}
		res = result.response
	case <-time.After(3 * time.Second):
		t.Fatal("SSE response headers were buffered before the second event")
	}
	defer res.Body.Close()
	reader := bufio.NewReader(res.Body)
	firstEvent := make(chan string, 1)
	readError := make(chan error, 1)
	go func() {
		line, err := reader.ReadString('\n')
		if err != nil {
			readError <- err
			return
		}
		firstEvent <- line
	}()
	select {
	case line := <-firstEvent:
		if line != "data: first\n" {
			t.Fatalf("first SSE line changed: %q", line)
		}
	case err := <-readError:
		t.Fatal(err)
	case <-time.After(3 * time.Second):
		t.Fatal("first SSE event was buffered until the second event")
	}
	release()
	remainder, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(remainder) != "\ndata: second\n\n" {
		t.Fatalf("remaining SSE stream changed: %q", remainder)
	}
}

func TestHealthDoesNotReachUpstream(t *testing.T) {
	var calls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := (&Server{Upstream: u}).Handler()
	for _, path := range []string{"/_nocyber/healthz", "/_nocyber/readyz"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != 200 {
			t.Fatal(rr.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("health reached upstream")
	}
}

func TestReadinessUsesCallbackAndHidesFailureDetails(t *testing.T) {
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	var readinessCalls atomic.Int64
	var unavailable atomic.Bool
	unavailable.Store(true)
	server := &Server{Upstream: u, Ready: func(context.Context) error {
		readinessCalls.Add(1)
		if unavailable.Load() {
			return errors.New("sqlite failure with internal-secret")
		}
		return nil
	}}
	h := server.Handler()
	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "http://guard/_nocyber/healthz", nil))
	if health.Code != http.StatusOK || readinessCalls.Load() != 0 {
		t.Fatalf("liveness depends on readiness: status=%d callbacks=%d", health.Code, readinessCalls.Load())
	}
	notReady := httptest.NewRecorder()
	h.ServeHTTP(notReady, httptest.NewRequest(http.MethodGet, "http://guard/_nocyber/readyz", nil))
	if notReady.Code != http.StatusServiceUnavailable || !strings.Contains(notReady.Body.String(), `"status":"not_ready"`) {
		t.Fatalf("unexpected not-ready response: status=%d body=%q", notReady.Code, notReady.Body.String())
	}
	if strings.Contains(notReady.Body.String(), "internal-secret") {
		t.Fatalf("readiness response leaked internal error: %s", notReady.Body.String())
	}
	unavailable.Store(false)
	ready := httptest.NewRecorder()
	h.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "http://guard/_nocyber/readyz", nil))
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected ready response: status=%d body=%q", ready.Code, ready.Body.String())
	}
	if readinessCalls.Load() != 2 || upstreamCalls.Load() != 0 {
		t.Fatalf("callbacks=%d upstream=%d", readinessCalls.Load(), upstreamCalls.Load())
	}
}
