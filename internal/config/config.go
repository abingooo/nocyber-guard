package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Config contains infrastructure settings. Runtime audit settings are kept in
// a separate immutable snapshot so a management update cannot race a request.
type Config struct {
	UpstreamURL       *url.URL
	ListenAddr        string
	AdminListenAddr   string
	DataDir           string
	MasterKey         []byte
	InitialAdminPass  string
	TrustedProxyCIDRs []string
	AuditBodyLimit    int64
	AIConcurrency     int
	AITimeout         time.Duration
	AIQueueTimeout    time.Duration
	AdminCookieSecure bool
}

func Load() (Config, error) {
	u := strings.TrimSpace(os.Getenv("NCG_UPSTREAM_URL"))
	if u == "" {
		return Config{}, errors.New("NCG_UPSTREAM_URL is required")
	}
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return Config{}, fmt.Errorf("invalid NCG_UPSTREAM_URL")
	}
	listen := envOr("NCG_LISTEN_ADDR", ":8080")
	adminListen := envOr("NCG_ADMIN_LISTEN_ADDR", "127.0.0.1:9090")
	if err := ValidateEndpointAgainstListeners(parsed, listen, adminListen); err != nil {
		return Config{}, fmt.Errorf("invalid NCG_UPSTREAM_URL: %w", err)
	}
	dataDir := envOr("NCG_DATA_DIR", "./data")
	if !filepath.IsAbs(dataDir) {
		if abs, e := filepath.Abs(dataDir); e == nil {
			dataDir = abs
		}
	}
	master, err := loadMasterKey(dataDir)
	if err != nil {
		return Config{}, err
	}
	adminPassword, err := loadSecret("NCG_INITIAL_ADMIN_PASSWORD", "NCG_INITIAL_ADMIN_PASSWORD_FILE")
	if err != nil {
		return Config{}, err
	}
	proxy := splitCSV(os.Getenv("NCG_TRUSTED_PROXY_CIDRS"))
	return Config{UpstreamURL: parsed, ListenAddr: listen, AdminListenAddr: adminListen, DataDir: dataDir,
		MasterKey: []byte(master), InitialAdminPass: adminPassword, TrustedProxyCIDRs: proxy,
		AuditBodyLimit: envInt64("NCG_AUDIT_BODY_LIMIT", 4<<20), AIConcurrency: int(envInt64("NCG_AI_CONCURRENCY", 16)),
		AITimeout: envDuration("NCG_AI_TIMEOUT", 15*time.Second), AIQueueTimeout: envDuration("NCG_AI_QUEUE_TIMEOUT", 2*time.Second),
		AdminCookieSecure: strings.EqualFold(os.Getenv("NCG_ADMIN_COOKIE_SECURE"), "true")}, nil
}

// ValidateEndpointAgainstListeners rejects endpoints that clearly resolve to
// one of this process's listeners. Hostname resolution is bounded and a DNS
// failure alone does not make an otherwise valid endpoint unusable.
func ValidateEndpointAgainstListeners(endpoint *url.URL, listeners ...string) error {
	if endpoint == nil || endpoint.Hostname() == "" {
		return errors.New("endpoint must be an absolute URL")
	}
	endpointPort, err := effectiveURLPort(endpoint)
	if err != nil {
		return err
	}
	for _, listener := range listeners {
		listenerHost, listenerPort, err := splitListener(listener)
		if err != nil {
			return err
		}
		if endpointPort == listenerPort && hostsCanAddressSameListener(endpoint.Hostname(), listenerHost) {
			return fmt.Errorf("endpoint points back to listener %q", listener)
		}
	}
	return nil
}

func effectiveURLPort(endpoint *url.URL) (int, error) {
	switch strings.ToLower(endpoint.Scheme) {
	case "http", "https":
	default:
		return 0, errors.New("endpoint scheme must be http or https")
	}
	if port := endpoint.Port(); port != "" {
		return parsePort(port)
	}
	switch strings.ToLower(endpoint.Scheme) {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	}
	return 0, errors.New("endpoint scheme must be http or https")
}

func splitListener(address string) (string, int, error) {
	if address == "" {
		address = ":http"
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listener address %q", address)
	}
	n, err := parsePort(port)
	if err != nil {
		return "", 0, fmt.Errorf("invalid listener address %q: %w", address, err)
	}
	return normalizeHost(host), n, nil
}

func parsePort(port string) (int, error) {
	if n, err := strconv.Atoi(port); err == nil {
		if n >= 0 && n <= 65535 {
			return n, nil
		}
		return 0, errors.New("port is out of range")
	}
	n, err := net.LookupPort("tcp", port)
	if err != nil {
		return 0, errors.New("unknown port")
	}
	return n, nil
}

func hostsCanAddressSameListener(endpointHost, listenerHost string) bool {
	endpointHost = normalizeHost(endpointHost)
	listenerHost = normalizeHost(listenerHost)
	if endpointHost == listenerHost {
		return true
	}
	endpointIP := parseHostIP(endpointHost)
	listenerIP := parseHostIP(listenerHost)
	if listenerHost == "" || (listenerIP != nil && listenerIP.IsUnspecified()) {
		return isDefinitelyLocalHost(endpointHost, endpointIP)
	}
	if endpointIP != nil && endpointIP.IsUnspecified() {
		return isDefinitelyLocalHost(listenerHost, listenerIP)
	}
	return isLoopbackHost(endpointHost, endpointIP) && isLoopbackHost(listenerHost, listenerIP)
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.Trim(host, "[]"))), ".")
}

func parseHostIP(host string) net.IP {
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	return net.ParseIP(host)
}

func isLoopbackHost(host string, ip net.IP) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || (ip != nil && ip.IsLoopback())
}

func isDefinitelyLocalHost(host string, ip net.IP) bool {
	if isLoopbackHost(host, ip) || (ip != nil && ip.IsUnspecified()) {
		return true
	}
	if localName, err := os.Hostname(); err == nil && normalizeHost(localName) == host {
		return true
	}
	if ip != nil {
		return isLocalInterfaceIP(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false
	}
	for _, address := range resolved {
		if address.IP.IsLoopback() || address.IP.IsUnspecified() || isLocalInterfaceIP(address.IP) {
			return true
		}
	}
	return false
}

func isLocalInterfaceIP(ip net.IP) bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addresses {
		var localIP net.IP
		switch value := address.(type) {
		case *net.IPNet:
			localIP = value.IP
		case *net.IPAddr:
			localIP = value.IP
		}
		if localIP != nil && localIP.Equal(ip) {
			return true
		}
	}
	return false
}

func envOr(k, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return fallback
}
func envInt64(k string, fallback int64) int64 {
	var n int64
	if _, e := fmt.Sscan(os.Getenv(k), &n); e == nil && n > 0 {
		return n
	}
	return fallback
}
func envDuration(k string, fallback time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		if d, e := time.ParseDuration(v); e == nil && d > 0 {
			return d
		}
	}
	return fallback
}
func splitCSV(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
func loadSecret(envName, fileName string) (string, error) {
	if value, ok := os.LookupEnv(envName); ok {
		return value, nil
	}
	if path := strings.TrimSpace(os.Getenv(fileName)); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", fileName, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return "", nil
}

func loadMasterKey(dataDir string) (string, error) {
	if value, err := loadSecret("NCG_MASTER_KEY", "NCG_MASTER_KEY_FILE"); err != nil {
		return "", err
	} else if strings.TrimSpace(value) != "" {
		return value, nil
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, "master.key")
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimRight(string(b), "\r\n"), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value := hex.EncodeToString(raw)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		b, readErr := os.ReadFile(path)
		return strings.TrimRight(string(b), "\r\n"), readErr
	}
	if err != nil {
		return "", err
	}
	if _, err = f.WriteString(value + "\n"); err != nil {
		_ = f.Close()
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return value, nil
}

type SnapshotStore struct{ v atomic.Value }

func NewSnapshotStore(initial any) *SnapshotStore {
	s := &SnapshotStore{}
	s.v.Store(initial)
	return s
}
func (s *SnapshotStore) Load() any   { return s.v.Load() }
func (s *SnapshotStore) Store(v any) { s.v.Store(v) }
