package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const imageRepository = "ghcr.io/abingooo/nocyber-guard"

var (
	versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	digestPattern  = regexp.MustCompile(`^ghcr\.io/abingooo/nocyber-guard@sha256:[a-f0-9]{64}$`)
)

type options struct {
	socket       string
	composeDir   string
	composeFiles []string
	envFile      string
	service      string
	healthURL    string
	stateFile    string
	socketGID    int
}

type operation struct {
	State       string `json:"state"`
	Action      string `json:"action,omitempty"`
	Target      string `json:"target_version,omitempty"`
	Message     string `json:"message,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

type persistentState struct {
	PreviousImage string `json:"previous_image,omitempty"`
	CurrentImage  string `json:"current_image,omitempty"`
}

type updater struct {
	opts          options
	logger        *slog.Logger
	mu            sync.RWMutex
	op            operation
	state         persistentState
	latestMu      sync.Mutex
	latestVersion string
	latestChecked time.Time
	latestErr     error
}

func main() {
	opts, err := loadOptions()
	if err != nil {
		slog.Error("updater_configuration_error", "error", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	u := &updater{opts: opts, logger: logger, op: operation{State: "idle"}}
	u.loadState()
	listener, err := listenUnix(opts.socket, opts.socketGID)
	if err != nil {
		logger.Error("updater_socket_error", "error", err)
		os.Exit(2)
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", u.handleStatus)
	mux.HandleFunc("POST /v1/update", u.handleUpdate)
	mux.HandleFunc("POST /v1/rollback", u.handleRollback)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	logger.Info("updater_listening", "socket", opts.socket, "compose_dir", opts.composeDir)
	if err = server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("updater_server_error", "error", err)
		os.Exit(1)
	}
}

func loadOptions() (options, error) {
	composeDir := envOr("NCG_UPDATER_COMPOSE_DIR", "/opt/nocyber-guard-main")
	gid, _ := strconv.Atoi(envOr("NCG_UPDATER_SOCKET_GID", "65532"))
	composeFiles := []string{envOr("NCG_UPDATER_COMPOSE_FILE", filepath.Join(composeDir, "docker-compose.yml"))}
	if override := strings.TrimSpace(os.Getenv("NCG_UPDATER_COMPOSE_OVERRIDE")); override != "" {
		composeFiles = append(composeFiles, override)
	}
	o := options{
		socket:       envOr("NCG_UPDATER_SOCKET", "/run/nocyber-updater/updater.sock"),
		composeDir:   composeDir,
		composeFiles: composeFiles,
		envFile:      envOr("NCG_UPDATER_ENV_FILE", filepath.Join(composeDir, ".env")),
		service:      envOr("NCG_UPDATER_SERVICE", "guard"),
		healthURL:    envOr("NCG_UPDATER_HEALTH_URL", "http://127.0.0.1:18086/_nocyber/readyz"),
		stateFile:    envOr("NCG_UPDATER_STATE_FILE", "/var/lib/nocyber-updater/state.json"),
		socketGID:    gid,
	}
	if !filepath.IsAbs(o.socket) || filepath.Ext(o.socket) != ".sock" || !filepath.IsAbs(o.composeDir) || !filepath.IsAbs(o.envFile) {
		return options{}, errors.New("socket, compose directory, compose file, and env file must be absolute paths")
	}
	for _, composeFile := range o.composeFiles {
		if !filepath.IsAbs(composeFile) {
			return options{}, errors.New("compose files must be absolute paths")
		}
	}
	if strings.ContainsAny(o.service, " \t\r\n/") || o.service == "" {
		return options{}, errors.New("invalid compose service")
	}
	return o, nil
}

func listenUnix(path string, gid int) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket %s", path)
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o660); err != nil {
		listener.Close()
		return nil, err
	}
	if gid >= 0 {
		if err = os.Chown(path, -1, gid); err != nil {
			listener.Close()
			return nil, err
		}
	}
	return listener, nil
}

func (u *updater) handleStatus(w http.ResponseWriter, r *http.Request) {
	latest, latestErr := u.latest(r.Context())
	u.mu.RLock()
	op := u.op
	state := u.state
	u.mu.RUnlock()
	current, err := readImage(u.opts.envFile)
	if err == nil {
		state.CurrentImage = current
	}
	out := map[string]any{
		"available":          true,
		"state":              op.State,
		"action":             op.Action,
		"target_version":     op.Target,
		"message":            op.Message,
		"started_at":         op.StartedAt,
		"completed_at":       op.CompletedAt,
		"current_image":      state.CurrentImage,
		"previous_image":     state.PreviousImage,
		"rollback_available": digestPattern.MatchString(state.PreviousImage),
	}
	if latestErr == nil {
		out["latest_version"] = latest
	} else {
		out["latest_error"] = "无法读取最新版本"
	}
	writeJSON(w, http.StatusOK, out)
}

func (u *updater) handleUpdate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	version := strings.TrimSpace(input.Version)
	if version == "" {
		var err error
		version, err = u.latest(r.Context())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"message": "无法获取最新版本"})
			return
		}
	}
	if !versionPattern.MatchString(version) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "版本号格式无效"})
		return
	}
	if !u.start("update", version) {
		writeJSON(w, http.StatusConflict, map[string]any{"message": "已有更新或回滚任务正在执行"})
		return
	}
	go u.runUpdate(version)
	writeJSON(w, http.StatusAccepted, map[string]any{"state": "running", "message": "更新任务已开始", "target_version": version})
}

func (u *updater) handleRollback(w http.ResponseWriter, _ *http.Request) {
	u.mu.RLock()
	previous := u.state.PreviousImage
	u.mu.RUnlock()
	if !digestPattern.MatchString(previous) {
		writeJSON(w, http.StatusConflict, map[string]any{"message": "没有可回滚的历史镜像"})
		return
	}
	if !u.start("rollback", previous) {
		writeJSON(w, http.StatusConflict, map[string]any{"message": "已有更新或回滚任务正在执行"})
		return
	}
	go u.runRollback(previous)
	writeJSON(w, http.StatusAccepted, map[string]any{"state": "running", "message": "回滚任务已开始"})
}

func (u *updater) start(action, target string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.op.State == "running" {
		return false
	}
	u.op = operation{State: "running", Action: action, Target: target, Message: "任务执行中", StartedAt: time.Now().UTC().Format(time.RFC3339)}
	return true
}

func (u *updater) finish(state, message string) {
	u.mu.Lock()
	u.op.State = state
	u.op.Message = message
	u.op.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	u.mu.Unlock()
}

func (u *updater) runUpdate(version string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	tag := strings.TrimPrefix(version, "v")
	tagged := imageRepository + ":" + tag
	if _, err := u.run(ctx, "docker", "pull", tagged); err != nil {
		u.finish("failed", "镜像下载失败")
		return
	}
	digest, err := u.resolveDigest(ctx, tagged)
	if err != nil {
		u.finish("failed", "无法验证镜像摘要")
		return
	}
	current, err := readImage(u.opts.envFile)
	if err != nil {
		u.finish("failed", "无法读取部署配置")
		return
	}
	if current == digest {
		u.finish("succeeded", "当前已是目标版本")
		return
	}
	if err = writeImage(u.opts.envFile, digest); err != nil {
		u.finish("failed", "无法写入部署配置")
		return
	}
	if err = u.recreateAndCheck(ctx); err != nil {
		rollbackErr := writeImage(u.opts.envFile, current)
		if rollbackErr == nil {
			rollbackErr = u.recreateAndCheck(ctx)
		}
		if rollbackErr != nil {
			u.finish("failed", "更新失败，自动回滚也未完成，请检查服务")
		} else {
			u.finish("failed", "更新健康检查失败，已自动回滚")
		}
		return
	}
	u.mu.Lock()
	u.state = persistentState{PreviousImage: current, CurrentImage: digest}
	u.saveStateLocked()
	u.mu.Unlock()
	u.finish("succeeded", "更新完成")
}

func (u *updater) runRollback(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	current, err := readImage(u.opts.envFile)
	if err != nil || writeImage(u.opts.envFile, target) != nil {
		u.finish("failed", "无法写入回滚配置")
		return
	}
	if err = u.recreateAndCheck(ctx); err != nil {
		_ = writeImage(u.opts.envFile, current)
		_ = u.recreateAndCheck(ctx)
		u.finish("failed", "回滚健康检查失败，已恢复原镜像")
		return
	}
	u.mu.Lock()
	u.state = persistentState{PreviousImage: current, CurrentImage: target}
	u.saveStateLocked()
	u.mu.Unlock()
	u.finish("succeeded", "回滚完成")
}

func (u *updater) resolveDigest(ctx context.Context, image string) (string, error) {
	out, err := u.run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image)
	if err != nil {
		return "", err
	}
	var digests []string
	if err = json.Unmarshal([]byte(strings.TrimSpace(out)), &digests); err != nil {
		return "", err
	}
	for _, digest := range digests {
		if digestPattern.MatchString(digest) {
			return digest, nil
		}
	}
	return "", errors.New("approved repository digest not found")
}

func (u *updater) recreateAndCheck(ctx context.Context) error {
	args := []string{"compose", "--project-directory", u.opts.composeDir, "--env-file", u.opts.envFile}
	for _, composeFile := range u.opts.composeFiles {
		args = append(args, "-f", composeFile)
	}
	args = append(args, "up", "-d", "--no-deps", u.opts.service)
	_, err := u.run(ctx, "docker", args...)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 4 * time.Second}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.opts.healthURL, nil)
		response, requestErr := client.Do(req)
		if requestErr == nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("health check timeout")
}

func (u *updater) run(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		u.logger.Error("updater_command_failed", "command", name, "args", args, "error", err, "output", strings.TrimSpace(string(output)))
		return "", err
	}
	return string(output), nil
}

func (u *updater) loadState() {
	b, err := os.ReadFile(u.opts.stateFile)
	if err == nil {
		_ = json.Unmarshal(b, &u.state)
	}
}

func (u *updater) saveStateLocked() {
	b, _ := json.MarshalIndent(u.state, "", "  ")
	_ = atomicWrite(u.opts.stateFile, append(b, '\n'), 0o600)
}

func (u *updater) latest(ctx context.Context) (string, error) {
	u.latestMu.Lock()
	defer u.latestMu.Unlock()
	if !u.latestChecked.IsZero() && time.Since(u.latestChecked) < 10*time.Minute {
		return u.latestVersion, u.latestErr
	}
	u.latestVersion, u.latestErr = latestRelease(ctx)
	u.latestChecked = time.Now()
	return u.latestVersion, u.latestErr
}

func latestRelease(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/abingooo/nocyber-guard/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "nocyber-updater")
	client := &http.Client{Timeout: 8 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub returned %d", response.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&release); err != nil {
		return "", err
	}
	if !versionPattern.MatchString(release.TagName) {
		return "", errors.New("latest release tag is invalid")
	}
	return release.TagName, nil
}

func readImage(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "NCG_IMAGE=") {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(trimmed, "NCG_IMAGE=")), `"'`), nil
		}
	}
	return "", errors.New("NCG_IMAGE is missing")
}

func writeImage(path, image string) error {
	if !digestPattern.MatchString(image) {
		return errors.New("image is not an approved digest")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "NCG_IMAGE=") {
			lines[i] = "NCG_IMAGE=" + image
			found = true
		}
	}
	if !found {
		lines = append(lines, "NCG_IMAGE="+image)
	}
	return atomicWrite(path, []byte(strings.Join(lines, "\n")), 0o600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".nocyber-update-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err = temp.Chmod(mode); err == nil {
		_, err = temp.Write(data)
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "请求 JSON 无效"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
