package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Auditor is deliberately small: the proxy never needs to know how rules or
// SQLite are implemented. A nil auditor means transparent pass-through.
type Auditor interface {
	Evaluate(ctx context.Context, req *http.Request, body []byte) (Decision, error)
}

type RouteAuditor interface{ ShouldAudit(*http.Request) bool }
type BodyLimitProvider interface{ AuditBodyLimit(*http.Request) int64 }
type Observer interface {
	Observe(context.Context, *http.Request, string)
}

type Decision struct {
	Allow       bool
	Blocked     bool
	Reason      string
	RequestID   string
	AuditMs     int64
	UAProfile   string
	Field       string
	Hash        string
	Model       string
	UpstreamHit bool
}

type Server struct {
	Upstream     *url.URL
	Auditor      Auditor
	Logger       *slog.Logger
	MaxBody      int64
	Ready        func(context.Context) error
	TrustedProxy func(net.IP) bool
}

var (
	errAuditBodyLimitExceeded     = errors.New("audit body limit exceeded")
	errUnsupportedContentEncoding = errors.New("unsupported Content-Encoding")
	errContentDecode              = errors.New("content decode failed")
)

func (s *Server) Handler() http.Handler {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	rp := &httputil.ReverseProxy{Transport: transport,
		FlushInterval: -1, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeUpstreamError(w, r, err)
		}}
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(s.Upstream)
		pr.Out.URL.RawQuery = pr.In.URL.RawQuery
		if len(pr.In.Trailer) > 0 {
			// Request.Clone copies the trailer map before a streaming body is
			// consumed. Share the inbound map so values populated at EOF reach
			// the upstream request instead of forwarding only empty keys.
			pr.Out.Trailer = pr.In.Trailer
		}
		s.setXForwarded(pr)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_nocyber/healthz" {
			s.health(w, r)
			return
		}
		if r.URL.Path == "/_nocyber/readyz" {
			s.ready(w, r)
			return
		}
		websocket := isWebSocket(r)
		if observer, ok := s.Auditor.(Observer); ok {
			if websocket {
				observer.Observe(r.Context(), r, "websocket_unreviewed_allow")
			} else if unsupportedProtocolPath(r.URL.Path) {
				observer.Observe(r.Context(), r, "protocol_unreviewed_allow")
			}
		}
		shouldAudit := !websocket && r.Method == http.MethodPost && ProtectedPath(r.URL.Path)
		if routeAuditor, ok := s.Auditor.(RouteAuditor); ok {
			shouldAudit = !websocket && routeAuditor.ShouldAudit(r)
		}
		if shouldAudit && s.Auditor != nil {
			bodyLimit := s.MaxBody
			if provider, ok := s.Auditor.(BodyLimitProvider); ok {
				if current := provider.AuditBodyLimit(r); current > 0 {
					bodyLimit = current
				}
			}
			body, replay, auditable, err := captureBody(r.Body, bodyLimit)
			r.Body = replay
			if !auditable {
				s.Logger.Warn("audit_body_bypass", "reason", err)
				if observer, ok := s.Auditor.(Observer); ok {
					observer.Observe(r.Context(), r, bodyBypassReason(err))
				}
				rp.ServeHTTP(w, r)
				return
			}
			contentEncoding := strings.Join(r.Header.Values("Content-Encoding"), ",")
			auditBody, err := decodeAuditBody(body, contentEncoding, bodyLimit)
			if err != nil {
				s.Logger.Warn("audit_body_bypass", "reason", err)
				if observer, ok := s.Auditor.(Observer); ok {
					observer.Observe(r.Context(), r, bodyBypassReason(err))
				}
				rp.ServeHTTP(w, r)
				return
			}
			decision, evalErr := s.Auditor.Evaluate(r.Context(), r, auditBody)
			if evalErr != nil {
				s.Logger.Warn("audit_fail_open", "error", evalErr)
			}
			if decision.Blocked {
				_ = r.Body.Close()
				writeBlocked(w, decision)
				return
			}
			r.Body = &replayBody{Reader: bytes.NewReader(body), closer: replay}
		}
		rp.ServeHTTP(w, r)
	})
}

// setXForwarded rebuilds forwarding metadata at the trust boundary. A trusted
// peer may supply a chain, but values to the left of the first untrusted or
// malformed hop cannot be authenticated and are discarded.
func (s *Server) setXForwarded(pr *httputil.ProxyRequest) {
	pr.Out.Header.Del("X-Forwarded-For")
	pr.Out.Header.Del("X-Forwarded-Host")
	pr.Out.Header.Del("X-Forwarded-Proto")
	pr.Out.Header.Del("X-Forwarded-Port")
	remoteHost, _, err := net.SplitHostPort(pr.In.RemoteAddr)
	remoteIP := net.ParseIP(remoteHost)
	trusted := err == nil && remoteIP != nil && s.TrustedProxy != nil && s.TrustedProxy(remoteIP)

	forwardedFor := make([]string, 0, 2)
	if trusted {
		forwardedFor = trustedForwardedFor(pr.In.Header.Values("X-Forwarded-For"), s.TrustedProxy)
	}
	if remoteIP != nil {
		forwardedFor = append(forwardedFor, remoteIP.String())
	}
	if len(forwardedFor) > 0 {
		pr.Out.Header.Set("X-Forwarded-For", strings.Join(forwardedFor, ", "))
	}

	forwardedHost := pr.In.Host
	if trusted {
		if value, ok := singleForwardedValue(pr.In.Header, "X-Forwarded-Host"); ok && validForwardedHost(value) {
			forwardedHost = value
		}
	}
	if validForwardedHost(forwardedHost) {
		pr.Out.Header.Set("X-Forwarded-Host", forwardedHost)
	}

	forwardedProto := requestScheme(pr.In)
	if trusted {
		if value, ok := singleForwardedValue(pr.In.Header, "X-Forwarded-Proto"); ok {
			value = strings.ToLower(value)
			if value == "http" || value == "https" {
				forwardedProto = value
			}
		}
	}
	pr.Out.Header.Set("X-Forwarded-Proto", forwardedProto)

	forwardedPort := requestPort(pr.In)
	if trusted {
		if value, ok := singleForwardedValue(pr.In.Header, "X-Forwarded-Port"); ok && validForwardedPort(value) {
			forwardedPort = value
		}
	}
	if forwardedPort != "" {
		pr.Out.Header.Set("X-Forwarded-Port", forwardedPort)
	}
}

func trustedForwardedFor(values []string, trustedProxy func(net.IP) bool) []string {
	var chain []string
	for _, value := range values {
		chain = append(chain, strings.Split(value, ",")...)
	}
	retained := make([]string, 0, len(chain))
	for index := len(chain) - 1; index >= 0; index-- {
		ip := net.ParseIP(strings.TrimSpace(chain[index]))
		if ip == nil {
			break
		}
		retained = append(retained, ip.String())
		if trustedProxy == nil || !trustedProxy(ip) {
			break
		}
	}
	for left, right := 0, len(retained)-1; left < right; left, right = left+1, right-1 {
		retained[left], retained[right] = retained[right], retained[left]
	}
	return retained
}

func singleForwardedValue(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	value := strings.TrimSpace(values[0])
	return value, value != "" && !strings.Contains(value, ",")
}

func validForwardedHost(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, " \t\r\n,/?#@") {
		return false
	}
	if strings.Count(value, ":") > 1 && !strings.HasPrefix(value, "[") {
		return false
	}
	parsed, err := url.Parse("http://" + value)
	if err != nil || parsed.Host != value || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" {
		return false
	}
	if strings.HasSuffix(value, ":") {
		return false
	}
	if port := parsed.Port(); port != "" && !validForwardedPort(port) {
		return false
	}
	return true
}

func validForwardedPort(value string) bool {
	if value == "" || len(value) > 5 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
}

func requestScheme(r *http.Request) string {
	if r != nil && r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestPort(r *http.Request) string {
	if r == nil {
		return ""
	}
	if host, port, err := net.SplitHostPort(r.Host); err == nil && host != "" {
		if validForwardedPort(port) {
			return port
		}
		return ""
	}
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

func ProtectedPath(p string) bool {
	return p == "/v1/responses" || p == "/responses" || p == "/backend-api/codex/responses"
}
func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") && headerHasToken(r.Header.Values("Connection"), "upgrade")
}
func headerHasToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}
func unsupportedProtocolPath(p string) bool {
	return strings.HasSuffix(p, "/chat/completions") || strings.HasSuffix(p, "/messages") || strings.Contains(p, ":generateContent") || strings.Contains(p, ":streamGenerateContent")
}

type replayBody struct {
	io.Reader
	closer io.Closer
}

func (b *replayBody) Close() error {
	if b.closer != nil {
		return b.closer.Close()
	}
	return nil
}

func captureBody(original io.ReadCloser, limit int64) ([]byte, io.ReadCloser, bool, error) {
	if original == nil {
		return nil, http.NoBody, true, nil
	}
	if limit <= 0 {
		limit = 4 << 20
	}
	b, err := io.ReadAll(io.LimitReader(original, limit+1))
	if err != nil {
		return b, &replayBody{Reader: io.MultiReader(bytes.NewReader(b), original), closer: original}, false, err
	}
	if int64(len(b)) > limit {
		return b, &replayBody{Reader: io.MultiReader(bytes.NewReader(b), original), closer: original}, false, errAuditBodyLimitExceeded
	}
	return b, &replayBody{Reader: bytes.NewReader(b), closer: original}, true, nil
}

func decodeAuditBody(body []byte, contentEncoding string, limit int64) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))
	if encoding == "" || encoding == "identity" {
		return body, nil
	}
	if encoding != "gzip" && encoding != "x-gzip" {
		return nil, errUnsupportedContentEncoding
	}
	if limit <= 0 {
		limit = 4 << 20
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: gzip: %v", errContentDecode, err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, limit+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("%w: gzip: %v", errContentDecode, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("%w: gzip close: %v", errContentDecode, closeErr)
	}
	if int64(len(decoded)) > limit {
		return nil, errAuditBodyLimitExceeded
	}
	return decoded, nil
}

func bodyBypassReason(err error) string {
	if errors.Is(err, errAuditBodyLimitExceeded) {
		return "oversize_bypass"
	}
	if errors.Is(err, errUnsupportedContentEncoding) {
		return "unsupported_content_encoding_fail_open"
	}
	if errors.Is(err, errContentDecode) {
		return "content_decode_fail_open"
	}
	return "body_read_fail_open"
}

func writeBlocked(w http.ResponseWriter, d Decision) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = io.WriteString(w, `{"error":{"message":"Your activity may violate our usage policies. Please contact the administrator.","type":"invalid_request_error","code":"nocyber_guard_blocked"}}`)
}

func writeUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) || (r != nil && errors.Is(r.Context().Err(), context.Canceled)) {
		return
	}
	timedOut := errors.Is(err, context.DeadlineExceeded)
	if !timedOut {
		var networkError net.Error
		timedOut = errors.As(err, &networkError) && networkError.Timeout()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if timedOut {
		w.WriteHeader(http.StatusGatewayTimeout)
		_, _ = io.WriteString(w, `{"error":{"message":"upstream timeout","type":"server_error","code":"upstream_timeout"}}`)
		return
	}
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, `{"error":{"message":"upstream unavailable","type":"server_error","code":"upstream_unavailable"}}`)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if s.Ready != nil {
		if err := s.Ready(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"not_ready"}`)
			return
		}
	}
	s.health(w, r)
}

// NewHTTPServer applies conservative timeouts to the public listener. The
// reverse proxy itself keeps streaming responses unbuffered.
func NewHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 90 * time.Second, ConnContext: func(ctx context.Context, c net.Conn) context.Context { return ctx }}
}
