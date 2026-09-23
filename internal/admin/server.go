package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abingooo/nocyber-guard/internal/buildinfo"
	"github.com/abingooo/nocyber-guard/internal/storage"
	webassets "github.com/abingooo/nocyber-guard/web"
)

const sessionCookie = "ncg_session"
const csrfCookie = "ncg_csrf"

type Server struct {
	Store              *storage.Store
	Logger             *slog.Logger
	FixedUpstreamURL   string
	SecureCookies      bool
	StartedAt          time.Time
	OnReload           func(context.Context) error
	ValidateUpstream   func(*url.URL) error
	ValidateAIEndpoint func(*url.URL) error
	FrameAncestors     func() []string
	TestAI             func(ctx *http.Request, endpoint storage.AIEndpoint) (time.Duration, error)
	UpdaterSocket      string
	limiter            *loginLimiter
}

func (s *Server) Handler() http.Handler {
	if s.Logger == nil {
		s.Logger = slog.Default()
	}
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now()
	}
	s.limiter = &loginLimiter{attempts: map[string][]time.Time{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_nocyber/healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /_nocyber/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := contextTimeout(r, 2*time.Second)
		defer cancel()
		if _, err := s.Store.GetConfig(ctx, s.FixedUpstreamURL); err != nil {
			writeError(w, 503, "not_ready", "database unavailable")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.Handle("/api/v1/", s.requireAuth(http.HandlerFunc(s.api)))
	dist, _ := fs.Sub(webassets.Dist, "dist")
	files := http.FileServer(http.FS(dist))
	mux.Handle("/", spaHandler(files, dist))
	return s.securityHeaders(mux)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.allow(ip, time.Now()) {
		writeError(w, 429, "login_rate_limited", "登录尝试过于频繁")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	token, csrf, exp, err := s.Store.Login(r.Context(), strings.TrimSpace(in.Username), in.Password)
	if err != nil {
		s.limiter.fail(ip, time.Now())
		writeError(w, 401, "invalid_credentials", "用户名或密码错误")
		return
	}
	s.limiter.success(ip)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode, Expires: exp, MaxAge: int(time.Until(exp).Seconds())})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: s.SecureCookies, SameSite: http.SameSiteStrictMode, Expires: exp, MaxAge: int(time.Until(exp).Seconds())})
	writeJSON(w, 200, map[string]any{"username": in.Username, "expires_at": exp.UTC().Format(time.RFC3339)})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, 401, "unauthorized", "请先登录")
			return
		}
		user, csrf, ok := s.Store.Session(r.Context(), cookie.Value)
		if !ok {
			clearCookies(w, s.SecureCookies)
			writeError(w, 401, "unauthorized", "会话已过期")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			csrfCookieValue, e := r.Cookie(csrfCookie)
			header := r.Header.Get("X-CSRF-Token")
			if e != nil || subtle.ConstantTimeCompare([]byte(header), []byte(csrf)) != 1 || subtle.ConstantTimeCompare([]byte(csrfCookieValue.Value), []byte(csrf)) != 1 {
				writeError(w, 403, "csrf_failed", "CSRF 校验失败")
				return
			}
		}
		r.Header.Set("X-NoCyber-Admin", user)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/auth/session" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"username": r.Header.Get("X-NoCyber-Admin")})
	case path == "/auth/logout" && r.Method == http.MethodPost:
		s.logout(w, r)
	case path == "/overview" && r.Method == http.MethodGet:
		s.overview(w, r)
	case path == "/config" && r.Method == http.MethodGet:
		s.getConfig(w, r)
	case path == "/config" && r.Method == http.MethodPut:
		s.putConfig(w, r)
	case path == "/ai-endpoint" && r.Method == http.MethodPut:
		s.putAI(w, r)
	case path == "/ai-endpoint/test" && r.Method == http.MethodPost:
		s.testAI(w, r)
	case path == "/ai-nodes" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
		s.asyncNodes(w, r)
	case strings.HasPrefix(path, "/ai-nodes/") && strings.HasSuffix(path, "/test") && r.Method == http.MethodPost:
		s.testAsyncNode(w, r, path)
	case path == "/review-jobs" && r.Method == http.MethodGet:
		s.reviewJobs(w, r)
	case path == "/system/update" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		s.systemUpdate(w, r)
	case path == "/system/rollback" && r.Method == http.MethodPost:
		s.systemRollback(w, r)
	case strings.HasPrefix(path, "/review-jobs/") && strings.HasSuffix(path, "/votes") && r.Method == http.MethodGet:
		s.reviewVotes(w, r, path)
	case path == "/trusted-hashes" || path == "/risk-hashes":
		s.hashCollection(w, r, path)
	case strings.HasPrefix(path, "/trusted-hashes/") || strings.HasPrefix(path, "/risk-hashes/"):
		s.hashItem(w, r, path)
	case path == "/client-profiles":
		s.profileCollection(w, r)
	case strings.HasPrefix(path, "/client-profiles/"):
		s.profileItem(w, r, path)
	case path == "/events" && (r.Method == http.MethodGet || r.Method == http.MethodDelete):
		if r.Method == http.MethodDelete {
			s.deleteEvents(w, r)
		} else {
			s.events(w, r)
		}
	case strings.HasPrefix(path, "/events/"):
		s.eventItem(w, r, path)
	default:
		writeError(w, 404, "not_found", "接口不存在")
	}
}

func (s *Server) systemUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		payload, status, err := s.callUpdater(r.Context(), http.MethodGet, "/v1/status", nil)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"available": false, "current_version": buildinfo.Version, "message": "更新服务未连接"})
			return
		}
		payload["available"] = status >= 200 && status < 300
		payload["current_version"] = buildinfo.Version
		writeJSON(w, http.StatusOK, payload)
		return
	}
	var input struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	payload, status, err := s.callUpdater(r.Context(), http.MethodPost, "/v1/update", input)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "updater_unavailable", "更新服务未连接")
		return
	}
	if status < 200 || status >= 300 {
		message, _ := payload["message"].(string)
		if message == "" {
			message = "无法开始更新"
		}
		writeError(w, status, "update_rejected", message)
		return
	}
	writeJSON(w, status, payload)
}

func (s *Server) systemRollback(w http.ResponseWriter, r *http.Request) {
	payload, status, err := s.callUpdater(r.Context(), http.MethodPost, "/v1/rollback", map[string]any{})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "updater_unavailable", "更新服务未连接")
		return
	}
	if status < 200 || status >= 300 {
		message, _ := payload["message"].(string)
		if message == "" {
			message = "无法开始回滚"
		}
		writeError(w, status, "rollback_rejected", message)
		return
	}
	writeJSON(w, status, payload)
}

func (s *Server) callUpdater(ctx context.Context, method, path string, body any) (map[string]any, int, error) {
	if strings.TrimSpace(s.UpdaterSocket) == "" {
		return nil, 0, errors.New("updater socket is not configured")
	}
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		requestBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://unix"+path, requestBody)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", s.UpdaterSocket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	var payload map[string]any
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, response.StatusCode, err
	}
	return payload, response.StatusCode, nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie(sessionCookie); e == nil {
		s.Store.Logout(r.Context(), c.Value)
	}
	clearCookies(w, s.SecureCookies)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	counts, err := s.Store.Overview(r.Context())
	if err != nil {
		writeError(w, 500, "storage_error", "读取概览失败")
		return
	}
	cfg, _ := s.Store.GetConfig(r.Context(), s.FixedUpstreamURL)
	counts["status"] = "healthy"
	counts["enabled"] = cfg.Enabled
	counts["mode"] = "permissive"
	counts["uptime_seconds"] = int64(time.Since(s.StartedAt).Seconds())
	endpoint, _ := s.Store.GetAIEndpoint(r.Context())
	counts["ai_configured"] = endpoint.BaseURL != "" && endpoint.Model != "" && endpoint.HasAPIKey
	counts["ai_model"] = endpoint.Model
	items, _ := s.Store.ListRecentEvents(r.Context(), 8)
	counts["recent_events"] = items
	writeJSON(w, 200, counts)
}
func (s *Server) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Store.GetConfig(r.Context(), s.FixedUpstreamURL)
	if err != nil {
		writeError(w, 500, "storage_error", "读取配置失败")
		return
	}
	endpoint, _ := s.Store.GetAIEndpoint(r.Context())
	endpoint.APIKey = ""
	out := mergeConfig(cfg, endpoint)
	nodes, err := s.Store.ListAINodes(r.Context())
	if err != nil {
		writeError(w, 500, "storage_error", "读取异步节点失败")
		return
	}
	for i := range nodes {
		nodes[i].APIKey = ""
	}
	out["async_nodes"] = nodes
	out["async_quorum"] = map[string]any{"risk": "2/3 reject", "trusted": "2/3 pass", "confidence": auditQuorumConfidence}
	writeJSON(w, 200, out)
}

const auditQuorumConfidence = 0.95

func (s *Server) asyncNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		nodes, err := s.Store.ListAINodes(r.Context())
		if err != nil {
			writeError(w, 500, "storage_error", "读取异步节点失败")
			return
		}
		for i := range nodes {
			nodes[i].APIKey = ""
		}
		writeJSON(w, 200, map[string]any{"items": nodes, "quorum": map[string]any{"risk": "2/3 reject", "trusted": "2/3 pass", "confidence": auditQuorumConfidence}})
		return
	}
	var input struct {
		Nodes []asyncNodeInput `json:"nodes"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if len(input.Nodes) != 3 {
		writeError(w, 400, "invalid_ai_nodes", "必须配置三个异步节点")
		return
	}
	seen := map[string]bool{}
	converted := make([]storage.AINode, 0, len(input.Nodes))
	for _, raw := range input.Nodes {
		node := raw.AINode()
		if seen[node.Slot] {
			writeError(w, 400, "invalid_ai_nodes", "异步节点 slot 不能重复")
			return
		}
		seen[node.Slot] = true
		if err := s.validateNode(node); err != nil {
			writeError(w, 400, "invalid_ai_node", err.Error())
			return
		}
		converted = append(converted, node)
	}
	for _, node := range converted {
		if err := s.Store.SaveAINode(r.Context(), node); err != nil {
			writeError(w, 500, "storage_error", "保存异步节点失败")
			return
		}
	}
	if !s.reloadRuntime(w, r) {
		return
	}
	savedNodes, err := s.Store.ListAINodes(r.Context())
	if err != nil {
		writeError(w, 500, "storage_error", "读取已保存异步节点失败")
		return
	}
	for i := range savedNodes {
		savedNodes[i].APIKey = ""
	}
	writeJSON(w, 200, map[string]any{"items": savedNodes, "quorum": map[string]any{"risk": "2/3 reject", "trusted": "2/3 pass", "confidence": auditQuorumConfidence}})
}

type asyncNodeInput struct {
	Slot      string `json:"slot"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	Model     string `json:"model"`
	APIKey    string `json:"api_key"`
	TimeoutMS int64  `json:"timeout_ms"`
	Enabled   bool   `json:"enabled"`
}

func (n asyncNodeInput) AINode() storage.AINode {
	return storage.AINode{Slot: n.Slot, Name: n.Name, BaseURL: n.BaseURL, Model: n.Model, APIKey: n.APIKey, TimeoutMS: n.TimeoutMS, Enabled: n.Enabled}
}

func (s *Server) validateNode(node storage.AINode) error {
	u, err := s.validateAIEndpoint(strings.TrimSpace(node.BaseURL))
	if err != nil {
		return errors.New("审核节点地址无效")
	}
	node.BaseURL = u.String()
	return storage.ValidateAINode(node)
}

func (s *Server) testAsyncNode(w http.ResponseWriter, r *http.Request, path string) {
	slot := strings.TrimSuffix(strings.TrimPrefix(path, "/ai-nodes/"), "/test")
	if slot != "async_1" && slot != "async_2" && slot != "async_3" {
		writeError(w, 404, "ai_node_not_found", "异步节点不存在")
		return
	}
	var input asyncNodeInput
	if !decodeJSON(w, r, &input) {
		return
	}
	nodes, err := s.Store.ListAINodes(r.Context())
	if err != nil {
		writeError(w, 500, "storage_error", "读取异步节点失败")
		return
	}
	var saved *storage.AINode
	for _, node := range nodes {
		if node.Slot == slot {
			candidate := node
			saved = &candidate
			break
		}
	}
	provided := input.Slot != "" || input.Name != "" || input.BaseURL != "" || input.Model != "" ||
		input.APIKey != "" || input.TimeoutMS != 0
	var node storage.AINode
	if provided {
		if input.Slot != "" && input.Slot != slot {
			writeError(w, 400, "invalid_ai_node", "异步节点 slot 与请求路径不一致")
			return
		}
		input.Slot = slot
		node = input.AINode()
		if node.APIKey == "" && saved != nil {
			node.APIKey = saved.APIKey
		}
	} else if saved != nil {
		node = *saved
	} else {
		writeError(w, 404, "ai_node_not_found", "异步节点不存在")
		return
	}
	u, err := s.validateAIEndpoint(strings.TrimSpace(node.BaseURL))
	if err != nil {
		writeError(w, 400, "invalid_ai_endpoint", "审核节点地址无效")
		return
	}
	node.BaseURL = u.String()
	if err := storage.ValidateAINode(node); err != nil {
		writeError(w, 400, "invalid_ai_node", err.Error())
		return
	}
	if s.TestAI == nil {
		writeError(w, 503, "ai_unavailable", "审核节点测试未配置")
		return
	}
	endpoint := storage.AIEndpoint{BaseURL: node.BaseURL, Model: node.Model, APIKey: node.APIKey, TimeoutMS: node.TimeoutMS, MaxConcurrency: 1}
	latency, testErr := s.TestAI(r, endpoint)
	if testErr != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "message": "节点测试失败"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "latency_ms": latency.Milliseconds(), "message": "节点响应正常"})
}

func (s *Server) reviewJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.Store.ListReviewJobs(r.Context(), limit)
	if err != nil {
		writeError(w, 500, "storage_error", "读取投票任务失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) reviewVotes(w http.ResponseWriter, r *http.Request, path string) {
	base := strings.TrimSuffix(path, "/votes")
	id, ok := lastID(base)
	if !ok {
		writeError(w, 400, "invalid_id", "任务 ID 无效")
		return
	}
	items, err := s.Store.ListReviewVotes(r.Context(), id)
	if err != nil {
		writeError(w, 500, "storage_error", "读取投票结果失败")
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
func mergeConfig(c storage.Config, e storage.AIEndpoint) map[string]any {
	b, _ := json.Marshal(c)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	out["ai_endpoint"] = e
	return out
}
func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var raw struct {
		storage.Config
		Expected *int64 `json:"expected_version"`
	}
	if !decodeJSON(w, r, &raw) {
		return
	}
	if raw.Expected == nil || *raw.Expected < 1 {
		writeError(w, 400, "expected_version_required", "expected_version 必须为正整数")
		return
	}
	expected := *raw.Expected
	raw.UpstreamURL = strings.TrimSpace(raw.UpstreamURL)
	if err := storage.ValidateConfig(raw.Config); err != nil {
		writeError(w, 400, "invalid_config", err.Error())
		return
	}
	upstream, err := url.Parse(raw.UpstreamURL)
	if err != nil {
		writeError(w, 400, "invalid_upstream", "上游服务地址无效")
		return
	}
	if s.ValidateUpstream != nil {
		if err = s.ValidateUpstream(upstream); err != nil {
			writeError(w, 400, "invalid_upstream", "上游服务地址不能指向 Guard 自身")
			return
		}
	}
	if err := s.Store.PutConfig(r.Context(), raw.Config, expected); err != nil {
		if strings.Contains(err.Error(), "version conflict") {
			writeError(w, 409, "version_conflict", "配置已被更新")
			return
		}
		writeError(w, 500, "storage_error", "保存配置失败")
		return
	}
	if !s.reloadRuntime(w, r) {
		return
	}
	saved, err := s.Store.GetConfig(r.Context(), s.FixedUpstreamURL)
	if err != nil {
		writeError(w, 500, "storage_error", "读取已保存配置失败")
		return
	}
	writeJSON(w, 200, saved)
}
func (s *Server) putAI(w http.ResponseWriter, r *http.Request) {
	var e struct {
		BaseURL        string `json:"base_url"`
		Model          string `json:"model"`
		APIKey         string `json:"api_key"`
		TimeoutMS      int64  `json:"timeout_ms"`
		MaxConcurrency int    `json:"max_concurrency"`
	}
	if !decodeJSON(w, r, &e) {
		return
	}
	u, err := s.validateAIEndpoint(strings.TrimSpace(e.BaseURL))
	if err != nil {
		writeError(w, 400, "invalid_ai_endpoint", "审核节点地址无效")
		return
	}
	item := storage.AIEndpoint{BaseURL: u.String(), Model: strings.TrimSpace(e.Model), APIKey: e.APIKey, TimeoutMS: e.TimeoutMS, MaxConcurrency: e.MaxConcurrency}
	if err = storage.ValidateAIEndpoint(item); err != nil {
		writeError(w, 400, "invalid_ai_config", err.Error())
		return
	}
	if err = s.Store.SaveAIEndpoint(r.Context(), item); err != nil {
		writeError(w, 500, "storage_error", "保存节点失败")
		return
	}
	if !s.reloadRuntime(w, r) {
		return
	}
	item.APIKey = ""
	saved, _ := s.Store.GetAIEndpoint(r.Context())
	item.HasAPIKey = saved.HasAPIKey
	writeJSON(w, 200, item)
}
func (s *Server) testAI(w http.ResponseWriter, r *http.Request) {
	var input struct {
		BaseURL        string `json:"base_url"`
		Model          string `json:"model"`
		APIKey         string `json:"api_key"`
		HasAPIKey      bool   `json:"has_api_key"`
		TimeoutMS      int64  `json:"timeout_ms"`
		MaxConcurrency int    `json:"max_concurrency"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	u, err := s.validateAIEndpoint(strings.TrimSpace(input.BaseURL))
	if err != nil {
		writeError(w, 400, "invalid_ai_endpoint", "审核节点地址无效")
		return
	}
	e := storage.AIEndpoint{BaseURL: u.String(), Model: strings.TrimSpace(input.Model), APIKey: input.APIKey, HasAPIKey: input.HasAPIKey, TimeoutMS: input.TimeoutMS, MaxConcurrency: input.MaxConcurrency}
	if err = storage.ValidateAIEndpoint(e); err != nil {
		writeError(w, 400, "invalid_ai_config", err.Error())
		return
	}
	if e.APIKey == "" {
		if saved, err := s.Store.GetAIEndpoint(r.Context()); err == nil && saved.HasAPIKey {
			e.APIKey = saved.APIKey
		}
	}
	if s.TestAI == nil {
		writeError(w, 503, "ai_unavailable", "审核节点测试未配置")
		return
	}
	latency, err := s.TestAI(r, e)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "message": "节点测试失败"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "latency_ms": latency.Milliseconds(), "message": "节点响应正常"})
}

func (s *Server) validateAIEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("AI endpoint must be an absolute http or https URL without credentials, query, or fragment")
	}
	if s.ValidateAIEndpoint != nil {
		if err := s.ValidateAIEndpoint(u); err != nil {
			return nil, err
		}
	}
	return u, nil
}

func (s *Server) hashCollection(w http.ResponseWriter, r *http.Request, path string) {
	kind := "trusted"
	if strings.Contains(path, "risk-") {
		kind = "risk"
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.Store.ListHashSummaries(r.Context(), kind)
		if err != nil {
			writeError(w, 500, "storage_error", "读取规则失败")
			return
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var in struct {
			SHA256            string `json:"sha256"`
			Label             string `json:"label"`
			Content           string `json:"content"`
			APIKeyFingerprint string `json:"api_key_fingerprint"`
			APIKeyHint        string `json:"api_key_hint"`
		}
		if !decodeJSONLimit(w, r, &in, 128<<20) {
			return
		}
		if in.Content == "" {
			writeError(w, 400, "rule_content_required", "规则原文不能为空")
			return
		}
		item, err := s.Store.AddHashSourceWithTrace(r.Context(), kind, in.SHA256, in.Label, in.Content, "manual", in.APIKeyFingerprint, in.APIKeyHint)
		if err != nil {
			writeError(w, 400, "invalid_hash", err.Error())
			return
		}
		if !s.reloadRuntime(w, r) {
			return
		}
		writeJSON(w, 201, item)
	default:
		w.WriteHeader(405)
	}
}
func (s *Server) hashItem(w http.ResponseWriter, r *http.Request, path string) {
	kind := "trusted"
	if strings.Contains(path, "risk-") {
		kind = "risk"
	}
	id, ok := lastID(path)
	if !ok {
		writeError(w, 400, "invalid_id", "ID 无效")
		return
	}
	switch r.Method {
	case http.MethodGet:
		item, err := s.Store.GetHash(r.Context(), kind, id)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, 404, "hash_not_found", "规则不存在")
			return
		}
		if err != nil {
			writeError(w, 500, "storage_error", "读取规则失败")
			return
		}
		writeJSON(w, 200, item)
	case http.MethodPut:
		var input struct {
			Label   string  `json:"label"`
			Enabled bool    `json:"enabled"`
			Content *string `json:"content,omitempty"`
		}
		if !decodeJSONLimit(w, r, &input, 128<<20) {
			return
		}
		item, err := s.Store.UpdateHashWithContent(r.Context(), kind, id, input.Label, input.Enabled, input.Content)
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, 404, "hash_not_found", "规则不存在")
			return
		}
		if err != nil {
			writeError(w, 400, "invalid_hash", err.Error())
			return
		}
		if !s.reloadRuntime(w, r) {
			return
		}
		writeJSON(w, 200, item)
	case http.MethodDelete:
		if err := s.Store.DeleteHash(r.Context(), kind, id); err != nil {
			writeError(w, 500, "storage_error", "删除失败")
			return
		}
		if !s.reloadRuntime(w, r) {
			return
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}
func (s *Server) profileCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := s.Store.ListProfiles(r.Context())
		if err != nil {
			writeError(w, 500, "storage_error", "读取客户端规则失败")
			return
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var p storage.ClientProfile
		if !decodeJSON(w, r, &p) {
			return
		}
		saved, err := s.Store.SaveProfile(r.Context(), p)
		if err != nil {
			writeError(w, 400, "invalid_profile", err.Error())
			return
		}
		if !s.reloadRuntime(w, r) {
			return
		}
		writeJSON(w, 201, saved)
	default:
		w.WriteHeader(405)
	}
}
func (s *Server) profileItem(w http.ResponseWriter, r *http.Request, path string) {
	id, ok := lastID(path)
	if !ok {
		writeError(w, 400, "invalid_id", "ID 无效")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var p storage.ClientProfile
		if !decodeJSON(w, r, &p) {
			return
		}
		p.ID = id
		saved, err := s.Store.SaveProfile(r.Context(), p)
		if err != nil {
			writeError(w, 400, "invalid_profile", err.Error())
			return
		}
		if !s.reloadRuntime(w, r) {
			return
		}
		writeJSON(w, 200, saved)
	case http.MethodDelete:
		if err := s.Store.DeleteProfile(r.Context(), id); err != nil {
			writeError(w, 500, "storage_error", "删除失败")
			return
		}
		if !s.reloadRuntime(w, r) {
			return
		}
		w.WriteHeader(204)
	default:
		w.WriteHeader(405)
	}
}

func (s *Server) reloadRuntime(w http.ResponseWriter, r *http.Request) bool {
	if s.OnReload == nil {
		return true
	}
	if err := s.OnReload(r.Context()); err != nil {
		s.Logger.Error("runtime_reload_failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "runtime_reload_failed", "配置已保存，但运行时重载失败；请重试或重启服务")
		return false
	}
	return true
}
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	from, err := parseEventDate(r.URL.Query().Get("from"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_event_date", "开始日期必须为 YYYY-MM-DD")
		return
	}
	to, err := parseEventDate(r.URL.Query().Get("to"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_event_date", "结束日期必须为 YYYY-MM-DD")
		return
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		writeError(w, http.StatusBadRequest, "invalid_event_date", "结束日期不能早于开始日期")
		return
	}
	// The UI presents inclusive calendar dates. Store the exclusive beginning
	// of the day after `to` so events on the selected end date are included.
	if !to.IsZero() {
		to = to.AddDate(0, 0, 1)
	}
	items, total, err := s.Store.ListEventsFiltered(r.Context(), page, size, storage.EventFilter{
		Decision: r.URL.Query().Get("decision"),
		Query:    r.URL.Query().Get("query"),
		From:     from,
		To:       to,
	})
	if err != nil {
		writeError(w, 500, "storage_error", "读取事件失败")
		return
	}
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 50
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func (s *Server) deleteEvents(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Scope  string `json:"scope"`
		Before string `json:"before,omitempty"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	var before *time.Time
	switch input.Scope {
	case "all":
		if input.Before != "" {
			writeError(w, http.StatusBadRequest, "invalid_event_cleanup", "清空全部事件时不能指定截止日期")
			return
		}
	case "before":
		parsed, err := parseEventCleanupCutoff(input.Before)
		if err != nil || parsed.IsZero() {
			writeError(w, http.StatusBadRequest, "invalid_event_cleanup", "截止时间必须为 YYYY-MM-DD 或 RFC3339")
			return
		}
		before = &parsed
	default:
		writeError(w, http.StatusBadRequest, "invalid_event_cleanup", "清理范围必须为 all 或 before")
		return
	}

	result, err := s.Store.DeleteEventsBefore(r.Context(), before)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage_error", "清理事件失败")
		return
	}
	if !result.WALTruncated && (result.DeletedEvents > 0 || result.DeletedEvidence > 0) {
		s.Logger.Warn("event_cleanup_wal_checkpoint_deferred", "deleted_events", result.DeletedEvents, "deleted_evidence", result.DeletedEvidence)
	}
	s.Logger.Info("admin_events_deleted", "admin", r.Header.Get("X-NoCyber-Admin"), "scope", input.Scope, "before", input.Before, "deleted_events", result.DeletedEvents, "deleted_evidence", result.DeletedEvidence)
	writeJSON(w, http.StatusOK, result)
}

func parseEventCleanupCutoff(value string) (time.Time, error) {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}
	return parseEventDate(value)
}

func parseEventDate(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if len(value) != len("2006-01-02") {
		return time.Time{}, errors.New("event date must use YYYY-MM-DD")
	}
	for i, r := range value {
		if i == 4 || i == 7 {
			if r != '-' {
				return time.Time{}, errors.New("event date must use YYYY-MM-DD")
			}
			continue
		}
		if r < '0' || r > '9' {
			return time.Time{}, errors.New("event date must use YYYY-MM-DD")
		}
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, errors.New("event date must use YYYY-MM-DD")
	}
	return parsed.UTC(), nil
}
func (s *Server) eventItem(w http.ResponseWriter, r *http.Request, path string) {
	evidence := strings.HasSuffix(path, "/evidence")
	base := strings.TrimSuffix(path, "/evidence")
	id, ok := lastID(base)
	if !ok {
		writeError(w, 400, "invalid_id", "ID 无效")
		return
	}
	if r.Method == http.MethodDelete {
		if evidence {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		result, err := s.Store.DeleteEvent(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "storage_error", "删除事件失败")
			return
		}
		if result.DeletedEvents == 0 {
			writeError(w, http.StatusNotFound, "event_not_found", "事件不存在")
			return
		}
		if !result.WALTruncated {
			s.Logger.Warn("event_delete_wal_checkpoint_deferred", "event_id", id, "deleted_evidence", result.DeletedEvidence)
		}
		s.Logger.Info("admin_event_deleted", "admin", r.Header.Get("X-NoCyber-Admin"), "event_id", id, "deleted_evidence", result.DeletedEvidence)
		writeJSON(w, http.StatusOK, result)
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if evidence {
		w.Header().Set("Cache-Control", "no-store")
		item, err := s.Store.GetEvidence(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeError(w, 404, "evidence_not_found", "证据不存在或已到期")
				return
			}
			writeError(w, 500, "storage_error", "读取证据失败")
			return
		}
		writeJSON(w, 200, item)
		return
	}
	item, err := s.Store.GetEvent(r.Context(), id)
	if err != nil {
		writeError(w, 404, "event_not_found", "事件不存在")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, item)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	return decodeJSONLimit(w, r, out, 1<<20)
}

func decodeJSONLimit(w http.ResponseWriter, r *http.Request, out any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		writeError(w, 400, "invalid_json", "请求 JSON 无效")
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, 400, "invalid_json", "只允许一个 JSON 值")
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
func clearCookies(w http.ResponseWriter, secure bool) {
	for _, name := range []string{sessionCookie, csrfCookie} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: name == sessionCookie, Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	}
}
func lastID(path string) (int64, bool) {
	part := path[strings.LastIndex(path, "/")+1:]
	id, err := strconv.ParseInt(part, 10, 64)
	return id, err == nil && id > 0
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func contextTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}

func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-time.Minute)
	list := l.attempts[ip][:0]
	for _, v := range l.attempts[ip] {
		if v.After(cut) {
			list = append(list, v)
		}
	}
	l.attempts[ip] = list
	return len(list) < 5
}
func (l *loginLimiter) fail(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.attempts[ip] = append(l.attempts[ip], now)
}
func (l *loginLimiter) success(ip string) { l.mu.Lock(); defer l.mu.Unlock(); delete(l.attempts, ip) }
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		ancestors := []string(nil)
		if s.FrameAncestors != nil {
			ancestors = s.FrameAncestors()
		}
		framePolicy := "'none'"
		if len(ancestors) > 0 {
			framePolicy = strings.Join(ancestors, " ")
		} else {
			w.Header().Set("X-Frame-Options", "DENY")
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors "+framePolicy)
		next.ServeHTTP(w, r)
	})
}
func spaHandler(files http.Handler, dist fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(dist, path); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			files.ServeHTTP(w, r2)
			return
		}
		files.ServeHTTP(w, r)
	})
}
