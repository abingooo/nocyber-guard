package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/abingooo/nocyber-guard/internal/audit"
	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

var hashPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

const (
	minAuditBodyBytes = 1 << 20
	maxAuditBodyBytes = 64 << 20
)

type Store struct {
	db        *sql.DB
	masterKey [32]byte
}

func Open(ctx context.Context, dataDir string, masterKey []byte) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "nocyber-guard.db")
	db, err := sql.Open("sqlite", sqliteDSN(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	s := &Store{db: db, masterKey: sha256.Sum256(masterKey)}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=NORMAL", "PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON", "PRAGMA secure_delete=ON"} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err = s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func sqliteDSN(path string) string {
	query := url.Values{}
	for _, pragma := range []string{
		"busy_timeout(5000)",
		"foreign_keys(ON)",
		"secure_delete(ON)",
		"synchronous(NORMAL)",
		"journal_mode(WAL)",
	} {
		query.Add("_pragma", pragma)
	}
	return "file:" + filepath.ToSlash(path) + "?" + query.Encode()
}
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_users(id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_sessions(token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_endpoints(id INTEGER PRIMARY KEY CHECK(id=1), base_url TEXT NOT NULL DEFAULT '', model TEXT NOT NULL DEFAULT '', api_key BLOB NOT NULL DEFAULT '', timeout_ms INTEGER NOT NULL DEFAULT 15000, max_concurrency INTEGER NOT NULL DEFAULT 16, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_nodes(id INTEGER PRIMARY KEY AUTOINCREMENT, slot TEXT NOT NULL UNIQUE, name TEXT NOT NULL DEFAULT '', base_url TEXT NOT NULL, model TEXT NOT NULL, api_key BLOB NOT NULL DEFAULT '', timeout_ms INTEGER NOT NULL DEFAULT 15000, enabled INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ai_nodes_enabled_idx ON ai_nodes(enabled,slot);
CREATE TABLE IF NOT EXISTS client_profiles(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER NOT NULL DEFAULT 100, matchers_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trusted_hashes(id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS risk_hashes(id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, method TEXT NOT NULL, path TEXT NOT NULL, protocol TEXT NOT NULL, model TEXT NOT NULL, user_agent TEXT NOT NULL, profile_key TEXT NOT NULL, decision TEXT NOT NULL, action TEXT NOT NULL DEFAULT 'audit', outcome TEXT NOT NULL DEFAULT 'allow', reason TEXT NOT NULL, field_name TEXT NOT NULL, sha256 TEXT NOT NULL, prompt_bytes INTEGER NOT NULL, prompt_runes INTEGER NOT NULL, ai_sampled INTEGER NOT NULL, ai_result TEXT NOT NULL DEFAULT '', ai_confidence REAL NOT NULL DEFAULT 0, ai_reason TEXT NOT NULL DEFAULT '', ai_category TEXT NOT NULL DEFAULT '', latency_ms INTEGER NOT NULL, audit_latency_ms INTEGER NOT NULL DEFAULT 0, ai_latency_ms INTEGER NOT NULL DEFAULT 0, upstream_accessed INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_reason_idx ON audit_events(reason);
CREATE TABLE IF NOT EXISTS blocked_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER NOT NULL REFERENCES audit_events(id) ON DELETE CASCADE, field_name TEXT NOT NULL, content TEXT NOT NULL, partial INTEGER NOT NULL DEFAULT 0, expires_at TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS guard_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS review_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, job_key TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, field_name TEXT NOT NULL, model TEXT NOT NULL DEFAULT '', sampled INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued', promotion TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '', sample_ciphertext BLOB NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL, completed_at TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS review_jobs_created_idx ON review_jobs(created_at DESC);
CREATE TABLE IF NOT EXISTS review_votes(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES review_jobs(id) ON DELETE CASCADE, node_slot TEXT NOT NULL, result TEXT NOT NULL DEFAULT '', confidence REAL NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '', latency_ms INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, UNIQUE(job_id,node_slot));
CREATE TABLE IF NOT EXISTS rule_promotions(id INTEGER PRIMARY KEY AUTOINCREMENT, job_id INTEGER NOT NULL REFERENCES review_jobs(id) ON DELETE CASCADE, sha256 TEXT NOT NULL, kind TEXT NOT NULL, vote_summary TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(job_id,kind));
`)
	if err != nil {
		return err
	}
	// Databases created by early release candidates may predate endpoint
	// tuning columns. Add them idempotently before the hot path reads them.
	if err := ensureColumn(ctx, s.db, "ai_endpoints", "timeout_ms", "INTEGER NOT NULL DEFAULT 15000"); err != nil {
		return err
	}
	if err := ensureColumn(ctx, s.db, "ai_endpoints", "max_concurrency", "INTEGER NOT NULL DEFAULT 16"); err != nil {
		return err
	}
	for _, column := range []struct{ name, definition string }{
		{"attempts", "INTEGER NOT NULL DEFAULT 0"},
		{"next_attempt_at", "TEXT NOT NULL DEFAULT ''"},
		{"last_error", "TEXT NOT NULL DEFAULT ''"},
		{"sample_ciphertext", "BLOB NOT NULL DEFAULT ''"},
		{"updated_at", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := ensureColumn(ctx, s.db, "review_jobs", column.name, column.definition); err != nil {
			return err
		}
	}
	for _, column := range []struct {
		name       string
		definition string
	}{
		{"action", "TEXT NOT NULL DEFAULT 'audit'"},
		{"outcome", "TEXT NOT NULL DEFAULT 'allow'"},
		{"audit_latency_ms", "INTEGER NOT NULL DEFAULT 0"},
		{"ai_latency_ms", "INTEGER NOT NULL DEFAULT 0"},
		{"upstream_accessed", "INTEGER NOT NULL DEFAULT 1"},
	} {
		if err := ensureColumn(ctx, s.db, "audit_events", column.name, column.definition); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = s.db.ExecContext(ctx, "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)", now); err != nil {
		return err
	}
	if err := s.migrateEventContractV2(ctx, now); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(3,?)", now)
	return err
}

func (s *Store) migrateEventContractV2(ctx context.Context, appliedAt string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var exists int
	err = tx.QueryRowContext(ctx, "SELECT 1 FROM schema_migrations WHERE version=2").Scan(&exists)
	if err == nil {
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	if _, err = tx.ExecContext(ctx, `UPDATE audit_events SET
		action=CASE WHEN reason IN ('disabled','route_bypass','protocol_unreviewed_allow','ua_bypass','websocket_unreviewed_allow','body_read_fail_open','unsupported_content_encoding_fail_open','content_decode_fail_open') THEN 'bypass' ELSE 'audit' END,
		outcome=CASE
			WHEN decision='block' THEN 'block'
			WHEN reason IN ('parse_bypass','empty_bypass','oversize_bypass','ai_uncertain','ai_low_confidence','ai_unavailable','ai_rate_limited','ai_timeout','ai_invalid','ai_bulkhead_fail_open','storage_fail_open','body_read_fail_open','unsupported_content_encoding_fail_open','content_decode_fail_open') THEN 'fail_open'
			ELSE 'allow' END,
		ai_reason='',
		ai_category='',
		audit_latency_ms=latency_ms,
		ai_latency_ms=CASE WHEN ai_latency_ms < 0 THEN 0 ELSE ai_latency_ms END,
		upstream_accessed=CASE WHEN decision='block' THEN 0 ELSE 1 END`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,applied_at) VALUES(2,?)", appliedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func ensureColumn(ctx context.Context, db *sql.DB, table, column, definition string) error {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition)
	return err
}

type Config struct {
	Version            int64    `json:"version"`
	Enabled            bool     `json:"enabled"`
	Mode               string   `json:"mode"`
	UpstreamURL        string   `json:"upstream_url"`
	ProtectedPaths     []string `json:"protected_paths"`
	RequestTimeoutMS   int64    `json:"request_timeout_ms"`
	MaxBodyBytes       int64    `json:"max_body_bytes"`
	EventRetentionDays int      `json:"event_retention_days"`
}

func defaultConfig(upstream string) Config {
	return Config{Version: 1, Enabled: true, Mode: "permissive", UpstreamURL: upstream, ProtectedPaths: []string{"/v1/responses", "/responses", "/backend-api/codex/responses"}, RequestTimeoutMS: 15000, MaxBodyBytes: 4 << 20, EventRetentionDays: 30}
}
func (s *Store) GetConfig(ctx context.Context, upstream string) (Config, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='guard_config'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		c := defaultConfig(upstream)
		return c, s.PutConfig(ctx, c, 0)
	}
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err = json.Unmarshal([]byte(raw), &c); err != nil {
		return Config{}, err
	}
	// The proxy target is infrastructure configuration. Never allow a value
	// persisted by an older build or submitted through the admin API to
	// override NCG_UPSTREAM_URL.
	if upstream != "" {
		c.UpstreamURL = upstream
	}
	return c, nil
}
func (s *Store) PutConfig(ctx context.Context, c Config, expected int64) error {
	if err := ValidateConfig(c); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var v int64
	var raw string
	e := tx.QueryRowContext(ctx, "SELECT version,value FROM settings WHERE key='guard_config'").Scan(&v, &raw)
	if e == nil && expected > 0 && v != expected {
		return fmt.Errorf("config version conflict: %d", v)
	}
	if errors.Is(e, sql.ErrNoRows) {
		v = 0
	} else if e != nil {
		return e
	}
	c.Version = v + 1
	b, _ = json.Marshal(c)
	_, err = tx.ExecContext(ctx, "INSERT INTO settings(key,value,version,updated_at) VALUES('guard_config',?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,version=excluded.version,updated_at=excluded.updated_at", string(b), c.Version, now)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ValidateConfig keeps invalid admin input out of SQLite so every successful
// update can be swapped into the in-memory audit snapshot immediately.
func ValidateConfig(c Config) error {
	if c.Mode != "permissive" {
		return errors.New("mode must be permissive")
	}
	if c.UpstreamURL != "" {
		u, err := url.Parse(c.UpstreamURL)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
			u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("upstream URL must be an absolute http or https URL without credentials, query, or fragment")
		}
	}
	if len(c.ProtectedPaths) == 0 || len(c.ProtectedPaths) > 64 {
		return errors.New("protected_paths must contain 1 to 64 exact paths")
	}
	seen := make(map[string]struct{}, len(c.ProtectedPaths))
	for _, protected := range c.ProtectedPaths {
		if protected == "" || len(protected) > 2048 || protected[0] != '/' || protected == "/" ||
			pathpkg.Clean(protected) != protected || strings.ContainsAny(protected, "?#\\\\") {
			return fmt.Errorf("invalid protected path %q", protected)
		}
		if _, duplicate := seen[protected]; duplicate {
			return fmt.Errorf("duplicate protected path %q", protected)
		}
		seen[protected] = struct{}{}
	}
	if c.RequestTimeoutMS < 100 || c.RequestTimeoutMS > 30000 {
		return errors.New("request_timeout_ms must be between 100 and 30000")
	}
	if c.MaxBodyBytes < minAuditBodyBytes || c.MaxBodyBytes > maxAuditBodyBytes {
		return errors.New("max_body_bytes must be between 1 MiB and 64 MiB")
	}
	if c.EventRetentionDays < 1 || c.EventRetentionDays > 3650 {
		return errors.New("event_retention_days must be between 1 and 3650")
	}
	return nil
}

type HashEntry struct {
	ID        int64  `json:"id"`
	SHA256    string `json:"sha256"`
	Label     string `json:"label"`
	Source    string `json:"source"`
	Enabled   bool   `json:"enabled"`
	CreatedAt string `json:"created_at"`
}

func validateHash(h string) error {
	if !hashPattern.MatchString(h) {
		return errors.New("sha256 must be 64 hexadecimal characters")
	}
	return nil
}
func (s *Store) LookupHash(ctx context.Context, h string) (audit.HashMatch, bool, error) {
	var m audit.HashMatch
	var label string
	err := s.db.QueryRowContext(ctx, "SELECT id,sha256,label FROM risk_hashes WHERE sha256=? AND enabled=1", strings.ToLower(h)).Scan(&m.ID, &m.SHA256, &label)
	if err == nil {
		m.Kind = "risk"
		m.Note = label
		return m, true, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return m, false, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT id,sha256,label FROM trusted_hashes WHERE sha256=? AND enabled=1", strings.ToLower(h)).Scan(&m.ID, &m.SHA256, &label)
	if err == nil {
		m.Kind = "trusted"
		m.Note = label
		return m, true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return m, false, nil
	}
	return m, false, err
}
func (s *Store) ListHashes(ctx context.Context, kind string) ([]HashEntry, error) {
	table := "trusted_hashes"
	if kind == "risk" {
		table = "risk_hashes"
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,sha256,label,source,enabled,created_at FROM "+table+" ORDER BY id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HashEntry{}
	for rows.Next() {
		var x HashEntry
		var en int
		if err = rows.Scan(&x.ID, &x.SHA256, &x.Label, &x.Source, &en, &x.CreatedAt); err != nil {
			return nil, err
		}
		x.Enabled = en != 0
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) AddHash(ctx context.Context, kind, h, label string) (HashEntry, error) {
	return s.AddHashSource(ctx, kind, h, label, "manual")
}

func (s *Store) AddHashSource(ctx context.Context, kind, h, label, source string) (HashEntry, error) {
	if kind != "trusted" && kind != "risk" {
		return HashEntry{}, errors.New("invalid hash kind")
	}
	if err := validateHash(h); err != nil {
		return HashEntry{}, err
	}
	label = strings.TrimSpace(label)
	if len(label) > 500 || !utf8.ValidString(label) {
		return HashEntry{}, errors.New("hash label must be valid UTF-8 and no longer than 500 bytes")
	}
	if source == "" || len(source) > 64 || !utf8.ValidString(source) {
		return HashEntry{}, errors.New("hash source is invalid")
	}
	table := "trusted_hashes"
	if kind == "risk" {
		table = "risk_hashes"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, "INSERT INTO "+table+"(sha256,label,source,created_at) VALUES(?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET label=excluded.label,source=excluded.source,enabled=1", strings.ToLower(h), label, source, now)
	if err != nil {
		return HashEntry{}, err
	}
	var x HashEntry
	var en int
	err = s.db.QueryRowContext(ctx, "SELECT id,sha256,label,source,enabled,created_at FROM "+table+" WHERE sha256=?", strings.ToLower(h)).Scan(&x.ID, &x.SHA256, &x.Label, &x.Source, &en, &x.CreatedAt)
	x.Enabled = en != 0
	return x, err
}

func (s *Store) UpdateHash(ctx context.Context, kind string, id int64, label string, enabled bool) (HashEntry, error) {
	if kind != "trusted" && kind != "risk" {
		return HashEntry{}, errors.New("invalid hash kind")
	}
	label = strings.TrimSpace(label)
	if len(label) > 500 || !utf8.ValidString(label) {
		return HashEntry{}, errors.New("hash label must be valid UTF-8 and no longer than 500 bytes")
	}
	table := "trusted_hashes"
	if kind == "risk" {
		table = "risk_hashes"
	}
	en := 0
	if enabled {
		en = 1
	}
	result, err := s.db.ExecContext(ctx, "UPDATE "+table+" SET label=?,enabled=? WHERE id=?", label, en, id)
	if err != nil {
		return HashEntry{}, err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return HashEntry{}, sql.ErrNoRows
	}
	var item HashEntry
	if err = s.db.QueryRowContext(ctx, "SELECT id,sha256,label,source,enabled,created_at FROM "+table+" WHERE id=?", id).Scan(&item.ID, &item.SHA256, &item.Label, &item.Source, &en, &item.CreatedAt); err != nil {
		return HashEntry{}, err
	}
	item.Enabled = en != 0
	return item, nil
}

func (s *Store) DeleteHash(ctx context.Context, kind string, id int64) error {
	if kind != "trusted" && kind != "risk" {
		return errors.New("invalid hash kind")
	}
	table := "trusted_hashes"
	if kind == "risk" {
		table = "risk_hashes"
	}
	result, err := s.db.ExecContext(ctx, "DELETE FROM "+table+" WHERE id=?", id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) RecordAuditEvent(ctx context.Context, e audit.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = s.insertEvent(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) insertEvent(ctx context.Context, tx *sql.Tx, e audit.Event) (int64, error) {
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	blocked := e.Decision == "block" || e.Outcome == audit.EventOutcomeBlock
	if e.Action == "" || e.Outcome == "" {
		e.Action, e.Outcome = audit.DeriveEventContract(e.Reason, blocked)
	}
	if e.Decision == "" {
		e.Decision = "allow"
		if e.Outcome == audit.EventOutcomeBlock {
			e.Decision = "block"
		}
	}
	if e.AuditLatency == 0 {
		e.AuditLatency = e.Latency
	}
	if e.AILatency == 0 && e.AIVerdict != nil {
		e.AILatency = time.Duration(e.AIVerdict.LatencyMS) * time.Millisecond
	}
	e.RequestID = safeEventText(e.RequestID, 128)
	e.Method = safeEventText(e.Method, 16)
	e.Path = safeEventText(e.Path, 2048)
	e.Protocol = safeEventText(e.Protocol, 64)
	e.Model = safeEventText(e.Model, 256)
	e.UserAgent = audit.SanitizeUserAgent(e.UserAgent)
	e.ProfileKey = safeEventText(e.ProfileKey, 64)
	e.Decision = safeEventText(e.Decision, 16)
	e.Field = safeEventText(e.Field, 64)
	if !hashPattern.MatchString(e.SHA256) {
		e.SHA256 = ""
	}
	if e.Outcome != audit.EventOutcomeBlock {
		// Events are committed before ReverseProxy runs. In v0.1 an allowed
		// outcome means the request is handed to the upstream exactly once.
		e.UpstreamAccessed = true
	}
	aiResult, aiConf := "", 0.0
	if e.AIVerdict != nil {
		aiResult = string(e.AIVerdict.Result)
		aiConf = e.AIVerdict.Confidence
	}
	upstreamAccessed := 0
	if e.UpstreamAccessed {
		upstreamAccessed = 1
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO audit_events(request_id,method,path,protocol,model,user_agent,profile_key,decision,action,outcome,reason,field_name,sha256,prompt_bytes,prompt_runes,ai_sampled,ai_result,ai_confidence,ai_reason,ai_category,latency_ms,audit_latency_ms,ai_latency_ms,upstream_accessed,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.RequestID, e.Method, e.Path, e.Protocol, e.Model, e.UserAgent, e.ProfileKey, e.Decision, string(e.Action), string(e.Outcome), string(e.Reason), e.Field, e.SHA256, e.PromptBytes, e.PromptRunes, e.AISampled, aiResult, aiConf, "", "", e.AuditLatency.Milliseconds(), e.AuditLatency.Milliseconds(), e.AILatency.Milliseconds(), upstreamAccessed, e.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func safeEventText(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}
func (s *Store) RecordBlockedEvent(ctx context.Context, e audit.Event, field, plaintext string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	id, err := s.insertEvent(ctx, tx, e)
	if err != nil {
		return err
	}
	content, partial := boundedEvidence(plaintext, 4<<20)
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO blocked_evidence(event_id,field_name,content,partial,expires_at,created_at) VALUES(?,?,?,?,?,?)", id, field, content, partial, now.Add(7*24*time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func boundedEvidence(v string, limit int) (string, bool) {
	b := []byte(v)
	if len(b) <= limit {
		return v, false
	}
	const marker = "\n\n[... evidence truncated ...]\n\n"
	if limit <= len(marker) {
		return marker[:max(0, limit)], true
	}
	contentBudget := limit - len(marker)
	firstEnd := contentBudget * 2 / 3
	for firstEnd > 0 && firstEnd < len(b) && !utf8.RuneStart(b[firstEnd]) {
		firstEnd--
	}
	lastBudget := contentBudget - contentBudget*2/3
	lastStart := len(b) - lastBudget
	for lastStart < len(b) && !utf8.RuneStart(b[lastStart]) {
		lastStart++
	}
	return string(b[:firstEnd]) + marker + string(b[lastStart:]), true
}

type Event struct {
	ID                int64   `json:"id"`
	RequestID         string  `json:"request_id"`
	CreatedAt         string  `json:"created_at"`
	Path              string  `json:"path"`
	Decision          string  `json:"decision"`
	Action            string  `json:"action"`
	Outcome           string  `json:"outcome"`
	Reason            string  `json:"reason"`
	FieldName         string  `json:"field_name"`
	ClientProfile     string  `json:"client_profile"`
	UserAgent         string  `json:"user_agent"`
	Model             string  `json:"model"`
	PromptSHA256      string  `json:"prompt_sha256"`
	AIResult          string  `json:"ai_result"`
	AIConfidence      float64 `json:"ai_confidence"`
	LatencyMS         int64   `json:"latency_ms"`
	AuditLatencyMS    int64   `json:"audit_latency_ms"`
	AILatencyMS       int64   `json:"ai_latency_ms"`
	UpstreamAccessed  bool    `json:"upstream_accessed"`
	EvidenceAvailable bool    `json:"evidence_available"`
}

// EventFilter contains optional filters for the administrative event list.
// From is inclusive and To is exclusive. Date-only callers should set To to
// the beginning of the following day to include the selected end date.
type EventFilter struct {
	Decision string
	Query    string
	From     time.Time
	To       time.Time
}

func (s *Store) ListEvents(ctx context.Context, page, size int, decision, query string) ([]Event, int64, error) {
	return s.ListEventsFiltered(ctx, page, size, EventFilter{Decision: decision, Query: query})
}

// ListEventsFiltered lists events with optional decision, text, and time
// bounds. The legacy ListEvents wrapper remains for callers without bounds.
func (s *Store) ListEventsFiltered(ctx context.Context, page, size int, filter EventFilter) ([]Event, int64, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 200 {
		size = 50
	}
	if !filter.From.IsZero() && !filter.To.IsZero() && filter.To.Before(filter.From) {
		return nil, 0, errors.New("event filter end must be after start")
	}
	where := "1=1"
	args := []any{}
	if filter.Decision != "" {
		where += " AND decision=?"
		args = append(args, filter.Decision)
	}
	if filter.Query != "" {
		where += " AND (request_id LIKE ? OR reason LIKE ? OR sha256 LIKE ?)"
		q := "%" + filter.Query + "%"
		args = append(args, q, q, q)
	}
	if !filter.From.IsZero() {
		where += " AND julianday(created_at) >= julianday(?)"
		args = append(args, filter.From.UTC().Format(time.RFC3339Nano))
	}
	if !filter.To.IsZero() {
		where += " AND julianday(created_at) < julianday(?)"
		args = append(args, filter.To.UTC().Format(time.RFC3339Nano))
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := []any{time.Now().UTC().Format(time.RFC3339Nano)}
	queryArgs = append(queryArgs, args...)
	queryArgs = append(queryArgs, size, (page-1)*size)
	rows, err := s.db.QueryContext(ctx, "SELECT id,request_id,created_at,path,decision,action,outcome,reason,field_name,profile_key,user_agent,model,sha256,ai_result,ai_confidence,audit_latency_ms,ai_latency_ms,upstream_accessed,EXISTS(SELECT 1 FROM blocked_evidence b WHERE b.event_id=audit_events.id AND b.expires_at>?) FROM audit_events WHERE "+where+" ORDER BY id DESC LIMIT ? OFFSET ?", queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.ID, &e.RequestID, &e.CreatedAt, &e.Path, &e.Decision, &e.Action, &e.Outcome, &e.Reason, &e.FieldName, &e.ClientProfile, &e.UserAgent, &e.Model, &e.PromptSHA256, &e.AIResult, &e.AIConfidence, &e.AuditLatencyMS, &e.AILatencyMS, &e.UpstreamAccessed, &e.EvidenceAvailable); err != nil {
			return nil, 0, err
		}
		e.LatencyMS = e.AuditLatencyMS
		out = append(out, e)
	}
	return out, total, rows.Err()
}
func (s *Store) GetEvent(ctx context.Context, id int64) (Event, error) {
	var e Event
	err := s.db.QueryRowContext(ctx, "SELECT id,request_id,created_at,path,decision,action,outcome,reason,field_name,profile_key,user_agent,model,sha256,ai_result,ai_confidence,audit_latency_ms,ai_latency_ms,upstream_accessed,EXISTS(SELECT 1 FROM blocked_evidence b WHERE b.event_id=audit_events.id AND b.expires_at>?) FROM audit_events WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id).Scan(&e.ID, &e.RequestID, &e.CreatedAt, &e.Path, &e.Decision, &e.Action, &e.Outcome, &e.Reason, &e.FieldName, &e.ClientProfile, &e.UserAgent, &e.Model, &e.PromptSHA256, &e.AIResult, &e.AIConfidence, &e.AuditLatencyMS, &e.AILatencyMS, &e.UpstreamAccessed, &e.EvidenceAvailable)
	e.LatencyMS = e.AuditLatencyMS
	return e, err
}

type Evidence struct {
	EventID    int64  `json:"event_id"`
	FieldName  string `json:"field_name"`
	Content    string `json:"content"`
	Partial    bool   `json:"partial"`
	CapturedAt string `json:"captured_at"`
}

func (s *Store) GetEvidence(ctx context.Context, id int64) (Evidence, error) {
	var e Evidence
	err := s.db.QueryRowContext(ctx, "SELECT event_id,field_name,content,partial,created_at FROM blocked_evidence WHERE event_id=? AND expires_at>?", id, time.Now().UTC().Format(time.RFC3339Nano)).Scan(&e.EventID, &e.FieldName, &e.Content, &e.Partial, &e.CapturedAt)
	return e, err
}

type ClientMatcher struct {
	Type          string `json:"type"`
	Value         string `json:"value"`
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
}
type ClientProfile struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	Matchers    []ClientMatcher `json:"matchers"`
	CreatedAt   string          `json:"created_at,omitempty"`
	UpdatedAt   string          `json:"updated_at,omitempty"`
}

func (s *Store) ListProfiles(ctx context.Context) ([]ClientProfile, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,description,enabled,priority,matchers_json,created_at,updated_at FROM client_profiles ORDER BY priority,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ClientProfile{}
	for rows.Next() {
		var p ClientProfile
		var en int
		var raw string
		if err = rows.Scan(&p.ID, &p.Name, &p.Description, &en, &p.Priority, &raw, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &p.Matchers)
		p.Enabled = en != 0
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) SaveProfile(ctx context.Context, p ClientProfile) (ClientProfile, error) {
	p.Name = strings.TrimSpace(p.Name)
	p.Description = strings.TrimSpace(p.Description)
	for i := range p.Matchers {
		p.Matchers[i].Type = strings.ToLower(strings.TrimSpace(p.Matchers[i].Type))
		p.Matchers[i].Value = strings.TrimSpace(p.Matchers[i].Value)
	}
	matchers := make([]audit.Matcher, 0, len(p.Matchers))
	for _, matcher := range p.Matchers {
		matchers = append(matchers, audit.Matcher{Type: matcher.Type, Value: matcher.Value, CaseSensitive: matcher.CaseSensitive})
	}
	if p.Priority < 0 || p.Priority > 999999 {
		return p, errors.New("profile priority must be between 0 and 999999")
	}
	if _, err := audit.NewProfileMatcher([]audit.ClientProfile{{
		Key: "profile_candidate", Name: p.Name, Description: p.Description,
		Enabled: p.Enabled, Priority: p.Priority, Matchers: matchers,
	}}); err != nil {
		return p, err
	}
	raw, _ := json.Marshal(p.Matchers)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	en := 0
	if p.Enabled {
		en = 1
	}
	var err error
	if p.ID == 0 {
		res, e := s.db.ExecContext(ctx, "INSERT INTO client_profiles(name,description,enabled,priority,matchers_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", p.Name, p.Description, en, p.Priority, string(raw), now, now)
		err = e
		if err == nil {
			p.ID, _ = res.LastInsertId()
		}
	} else {
		_, err = s.db.ExecContext(ctx, "UPDATE client_profiles SET name=?,description=?,enabled=?,priority=?,matchers_json=?,updated_at=? WHERE id=?", p.Name, p.Description, en, p.Priority, string(raw), now, p.ID)
	}
	p.CreatedAt = now
	p.UpdatedAt = now
	return p, err
}
func (s *Store) DeleteProfile(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM client_profiles WHERE id=?", id)
	return err
}

type AIEndpoint struct {
	BaseURL        string `json:"base_url"`
	Model          string `json:"model"`
	APIKey         string `json:"-"`
	HasAPIKey      bool   `json:"has_api_key"`
	TimeoutMS      int64  `json:"timeout_ms"`
	MaxConcurrency int    `json:"max_concurrency"`
}

// AINode is a separately configurable reviewer. Slot "sync" is represented
// by the legacy ai_endpoints row; async_1..async_3 are the v0.3 quorum nodes.
type AINode struct {
	ID        int64  `json:"id"`
	Slot      string `json:"slot"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	Model     string `json:"model"`
	APIKey    string `json:"-"`
	HasAPIKey bool   `json:"has_api_key"`
	TimeoutMS int64  `json:"timeout_ms"`
	Enabled   bool   `json:"enabled"`
}

func ValidateAINode(n AINode) error {
	if n.Slot != "async_1" && n.Slot != "async_2" && n.Slot != "async_3" {
		return errors.New("AI node slot must be async_1, async_2, or async_3")
	}
	if len(n.Name) > 128 || !utf8.ValidString(n.Name) {
		return errors.New("AI node name is invalid")
	}
	if n.BaseURL == "" {
		return errors.New("AI node URL is required")
	}
	u, err := url.Parse(strings.TrimSpace(n.BaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("AI node URL must be an absolute http or https URL without credentials, query, or fragment")
	}
	if strings.TrimSpace(n.Model) == "" || len(n.Model) > 256 || !utf8.ValidString(n.Model) {
		return errors.New("AI node model is required and must be no longer than 256 bytes")
	}
	if n.TimeoutMS < 100 || n.TimeoutMS > 30000 {
		return errors.New("AI node timeout_ms must be between 100 and 30000")
	}
	if len(n.APIKey) > 16<<10 {
		return errors.New("AI node API key is too long")
	}
	return nil
}

func (s *Store) ListAINodes(ctx context.Context) ([]AINode, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,slot,name,base_url,model,api_key,timeout_ms,enabled FROM ai_nodes ORDER BY slot")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AINode
	for rows.Next() {
		var n AINode
		var key []byte
		var enabled int
		if err := rows.Scan(&n.ID, &n.Slot, &n.Name, &n.BaseURL, &n.Model, &key, &n.TimeoutMS, &enabled); err != nil {
			return nil, err
		}
		n.Enabled = enabled != 0
		n.HasAPIKey = len(key) > 0
		if len(key) > 0 {
			plain, err := s.decrypt(key)
			if err != nil {
				return nil, err
			}
			n.APIKey = string(plain)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) SaveAINode(ctx context.Context, n AINode) error {
	n.Slot, n.Name, n.BaseURL, n.Model = strings.TrimSpace(n.Slot), strings.TrimSpace(n.Name), strings.TrimSpace(n.BaseURL), strings.TrimSpace(n.Model)
	if err := ValidateAINode(n); err != nil {
		return err
	}
	// Keep an empty API key as a non-NULL zero-length blob. ai_nodes.api_key is
	// NOT NULL, and SQLite checks that constraint before applying the conflict
	// update below. Passing a nil []byte would therefore fail before the
	// existing encrypted key can be preserved.
	encrypted := []byte{}
	var err error
	if n.APIKey != "" {
		encrypted, err = s.encrypt([]byte(n.APIKey))
		if err != nil {
			return err
		}
	}
	en := 0
	if n.Enabled {
		en = 1
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `INSERT INTO ai_nodes(slot,name,base_url,model,api_key,timeout_ms,enabled,updated_at) VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(slot) DO UPDATE SET name=excluded.name,base_url=excluded.base_url,model=excluded.model,api_key=CASE WHEN length(excluded.api_key)=0 THEN ai_nodes.api_key ELSE excluded.api_key END,timeout_ms=excluded.timeout_ms,enabled=excluded.enabled,updated_at=excluded.updated_at`, n.Slot, n.Name, n.BaseURL, n.Model, encrypted, n.TimeoutMS, en, now)
	return err
}

type ReviewJob struct {
	ID            int64  `json:"id"`
	JobKey        string `json:"job_key"`
	SHA256        string `json:"sha256"`
	FieldName     string `json:"field_name"`
	Model         string `json:"model"`
	Sampled       bool   `json:"sampled"`
	Status        string `json:"status"`
	Promotion     string `json:"promotion"`
	Attempts      int    `json:"attempts"`
	NextAttemptAt string `json:"next_attempt_at"`
	LastError     string `json:"last_error,omitempty"`
	CreatedAt     string `json:"created_at"`
	CompletedAt   string `json:"completed_at"`
}

type ReviewVote struct {
	ID         int64   `json:"id"`
	JobID      int64   `json:"job_id"`
	NodeSlot   string  `json:"node_slot"`
	Result     string  `json:"result"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Category   string  `json:"category"`
	LatencyMS  int64   `json:"latency_ms"`
	Error      string  `json:"error,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

type RulePromotion struct {
	ID          int64  `json:"id"`
	JobID       int64  `json:"job_id"`
	SHA256      string `json:"sha256"`
	Kind        string `json:"kind"`
	VoteSummary string `json:"vote_summary"`
	CreatedAt   string `json:"created_at"`
}

func (s *Store) CreateReviewJob(ctx context.Context, jobKey, sha256Value, fieldName, model, content string, sampled bool) (ReviewJob, bool, error) {
	if err := validateHash(sha256Value); err != nil {
		return ReviewJob{}, false, err
	}
	jobKey = strings.TrimSpace(jobKey)
	if jobKey == "" || len(jobKey) > 256 {
		return ReviewJob{}, false, errors.New("review job key is invalid")
	}
	sampledInt := 0
	if sampled {
		sampledInt = 1
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var encrypted []byte
	var err error
	if content != "" {
		encrypted, err = s.encrypt([]byte(content))
		if err != nil {
			return ReviewJob{}, false, err
		}
	}
	res, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO review_jobs(job_key,sha256,field_name,model,sampled,status,sample_ciphertext,created_at,updated_at) VALUES(?,?,?,?,?,'queued',?,?,?)", jobKey, strings.ToLower(sha256Value), fieldName, model, sampledInt, encrypted, now, now)
	if err != nil {
		return ReviewJob{}, false, err
	}
	created := false
	if n, _ := res.RowsAffected(); n > 0 {
		created = true
	}
	var j ReviewJob
	var sampledDB int
	err = s.db.QueryRowContext(ctx, "SELECT id,job_key,sha256,field_name,model,sampled,status,promotion,attempts,next_attempt_at,last_error,created_at,completed_at FROM review_jobs WHERE job_key=?", jobKey).Scan(&j.ID, &j.JobKey, &j.SHA256, &j.FieldName, &j.Model, &sampledDB, &j.Status, &j.Promotion, &j.Attempts, &j.NextAttemptAt, &j.LastError, &j.CreatedAt, &j.CompletedAt)
	j.Sampled = sampledDB != 0
	return j, created, err
}

func (s *Store) LoadReviewJobSample(ctx context.Context, id int64) (string, error) {
	var encrypted []byte
	if err := s.db.QueryRowContext(ctx, "SELECT sample_ciphertext FROM review_jobs WHERE id=?", id).Scan(&encrypted); err != nil {
		return "", err
	}
	if len(encrypted) == 0 {
		return "", nil
	}
	plain, err := s.decrypt(encrypted)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *Store) MarkReviewJobRunning(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, "UPDATE review_jobs SET status='running',attempts=attempts+1,updated_at=? WHERE id=?", time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

// ClaimReviewJob atomically claims a queued/retryable job. This prevents the
// recovery ticker and a duplicate enqueue from running the same hash twice.
func (s *Store) ClaimReviewJob(ctx context.Context, id int64) (bool, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, "UPDATE review_jobs SET status='running',attempts=attempts+1,updated_at=? WHERE id=? AND status IN ('queued','retry_pending') AND (next_attempt_at='' OR next_attempt_at<=?) AND attempts<3", now, id, now)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *Store) ScheduleReviewRetry(ctx context.Context, id int64, errText string, delay time.Duration) error {
	if delay < time.Second {
		delay = time.Second
	}
	if len(errText) > 500 {
		errText = errText[:500]
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, "UPDATE review_jobs SET status='retry_pending',next_attempt_at=?,last_error=?,updated_at=? WHERE id=?", now.Add(delay).Format(time.RFC3339Nano), errText, now.Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) ListDueReviewJobs(ctx context.Context, limit int) ([]ReviewJob, error) {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	rows, err := s.db.QueryContext(ctx, "SELECT id,job_key,sha256,field_name,model,sampled,status,promotion,attempts,next_attempt_at,last_error,created_at,completed_at FROM review_jobs WHERE status IN ('queued','retry_pending') AND (next_attempt_at='' OR next_attempt_at<=?) ORDER BY id LIMIT ?", now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewJob
	for rows.Next() {
		var j ReviewJob
		var sampled int
		if err := rows.Scan(&j.ID, &j.JobKey, &j.SHA256, &j.FieldName, &j.Model, &sampled, &j.Status, &j.Promotion, &j.Attempts, &j.NextAttemptAt, &j.LastError, &j.CreatedAt, &j.CompletedAt); err != nil {
			return nil, err
		}
		j.Sampled = sampled != 0
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) RequeueStaleReviewJobs(ctx context.Context, age time.Duration) error {
	if age < time.Minute {
		age = 2 * time.Minute
	}
	cutoff := time.Now().UTC().Add(-age).Format(time.RFC3339Nano)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, "UPDATE review_jobs SET status='completed_no_quorum',last_error='worker_restarted_after_max_attempts',completed_at=?,updated_at=? WHERE status='running' AND attempts>=3 AND (updated_at='' OR updated_at<?)", now, now, cutoff); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, "UPDATE review_jobs SET status='retry_pending',next_attempt_at='',last_error='worker_restarted',updated_at=? WHERE status='running' AND attempts<3 AND (updated_at='' OR updated_at<?)", now, cutoff)
	return err
}

func (s *Store) RecordReviewVote(ctx context.Context, v ReviewVote) error {
	if v.JobID < 1 || v.NodeSlot == "" {
		return errors.New("invalid review vote")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `INSERT INTO review_votes(job_id,node_slot,result,confidence,reason,category,latency_ms,error,created_at) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(job_id,node_slot) DO UPDATE SET result=excluded.result,confidence=excluded.confidence,reason=excluded.reason,category=excluded.category,latency_ms=excluded.latency_ms,error=excluded.error,created_at=excluded.created_at`, v.JobID, v.NodeSlot, v.Result, v.Confidence, v.Reason, v.Category, v.LatencyMS, v.Error, now)
	return err
}

func (s *Store) CompleteReviewJob(ctx context.Context, id int64, status, promotion string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE review_jobs SET status=?,promotion=?,completed_at=? WHERE id=?", status, promotion, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func (s *Store) PromoteHash(ctx context.Context, jobID int64, sha256Value, kind, summary string) error {
	if kind != "trusted" && kind != "risk" {
		return errors.New("invalid promotion kind")
	}
	if err := validateHash(sha256Value); err != nil {
		return err
	}
	table := "trusted_hashes"
	if kind == "risk" {
		table = "risk_hashes"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO "+table+"(sha256,label,source,created_at) VALUES(?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET label=excluded.label,source=excluded.source,enabled=1", strings.ToLower(sha256Value), "automatic async quorum", "async_quorum", now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO rule_promotions(job_id,sha256,kind,vote_summary,created_at) VALUES(?,?,?,?,?)", jobID, strings.ToLower(sha256Value), kind, summary, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListReviewJobs(ctx context.Context, limit int) ([]ReviewJob, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,job_key,sha256,field_name,model,sampled,status,promotion,attempts,next_attempt_at,last_error,created_at,completed_at FROM review_jobs ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewJob
	for rows.Next() {
		var j ReviewJob
		var sampled int
		if err := rows.Scan(&j.ID, &j.JobKey, &j.SHA256, &j.FieldName, &j.Model, &sampled, &j.Status, &j.Promotion, &j.Attempts, &j.NextAttemptAt, &j.LastError, &j.CreatedAt, &j.CompletedAt); err != nil {
			return nil, err
		}
		j.Sampled = sampled != 0
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) ListReviewVotes(ctx context.Context, jobID int64) ([]ReviewVote, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,job_id,node_slot,result,confidence,reason,category,latency_ms,error,created_at FROM review_votes WHERE job_id=? ORDER BY node_slot", jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReviewVote
	for rows.Next() {
		var v ReviewVote
		if err := rows.Scan(&v.ID, &v.JobID, &v.NodeSlot, &v.Result, &v.Confidence, &v.Reason, &v.Category, &v.LatencyMS, &v.Error, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func ValidateAIEndpoint(e AIEndpoint) error {
	if len(e.BaseURL) > 2048 {
		return errors.New("AI endpoint URL is too long")
	}
	u, err := url.Parse(strings.TrimSpace(e.BaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("AI endpoint must be an absolute http or https URL without credentials, query, or fragment")
	}
	model := strings.TrimSpace(e.Model)
	if model == "" || len(model) > 256 || !utf8.ValidString(model) {
		return errors.New("AI model is required and must be no longer than 256 bytes")
	}
	if e.TimeoutMS < 100 || e.TimeoutMS > 30000 {
		return errors.New("AI timeout_ms must be between 100 and 30000")
	}
	if e.MaxConcurrency < 1 || e.MaxConcurrency > 256 {
		return errors.New("AI max_concurrency must be between 1 and 256")
	}
	if len(e.APIKey) > 16<<10 {
		return errors.New("AI API key is too long")
	}
	return nil
}

func (s *Store) GetAIEndpoint(ctx context.Context) (AIEndpoint, error) {
	var e AIEndpoint
	var key []byte
	err := s.db.QueryRowContext(ctx, "SELECT base_url,model,api_key,timeout_ms,max_concurrency FROM ai_endpoints WHERE id=1").Scan(&e.BaseURL, &e.Model, &key, &e.TimeoutMS, &e.MaxConcurrency)
	if errors.Is(err, sql.ErrNoRows) {
		return e, nil
	}
	if err != nil {
		return e, err
	}
	e.HasAPIKey = len(key) > 0
	if len(key) > 0 {
		plain, decErr := s.decrypt(key)
		if decErr != nil {
			return e, decErr
		}
		e.APIKey = string(plain)
	}
	return e, nil
}
func (s *Store) SaveAIEndpoint(ctx context.Context, e AIEndpoint) error {
	e.BaseURL = strings.TrimSpace(e.BaseURL)
	e.Model = strings.TrimSpace(e.Model)
	if err := ValidateAIEndpoint(e); err != nil {
		return err
	}
	encrypted := []byte{}
	var err error
	if e.APIKey != "" {
		encrypted, err = s.encrypt([]byte(e.APIKey))
		if err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, "INSERT INTO ai_endpoints(id,base_url,model,api_key,timeout_ms,max_concurrency,updated_at) VALUES(1,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url,model=excluded.model,api_key=CASE WHEN length(excluded.api_key)=0 THEN ai_endpoints.api_key ELSE excluded.api_key END,timeout_ms=excluded.timeout_ms,max_concurrency=excluded.max_concurrency,updated_at=excluded.updated_at", e.BaseURL, e.Model, encrypted, e.TimeoutMS, e.MaxConcurrency, now)
	return err
}
func (s *Store) encrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte("nocyber-guard:ai-key:v1")), nil
}
func (s *Store) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("invalid encrypted secret")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, data, []byte("nocyber-guard:ai-key:v1"))
}

func (s *Store) EnsureAdmin(ctx context.Context, username, password string) error {
	if username == "" {
		username = "admin"
	}
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM admin_users").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if password == "" {
		return errors.New("NCG_INITIAL_ADMIN_PASSWORD or NCG_INITIAL_ADMIN_PASSWORD_FILE is required on first startup")
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("generate password hash: %w", err)
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO admin_users(username,password_hash,created_at,updated_at) VALUES(?,?,?,?)", username, hash, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}
func HashPassword(password string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return []byte(fmt.Sprintf("$argon2id$v=19$m=65536,t=1,p=4$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(key))), nil
}
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return false
	}
	salt, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
func (s *Store) Login(ctx context.Context, username, password string) (token, csrf string, expires time.Time, err error) {
	var hash string
	if err = s.db.QueryRowContext(ctx, "SELECT password_hash FROM admin_users WHERE username=?", username).Scan(&hash); err != nil || !VerifyPassword(hash, password) {
		return "", "", time.Time{}, errors.New("invalid credentials")
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate session token: %w", err)
	}
	c := make([]byte, 24)
	if _, err = rand.Read(c); err != nil {
		return "", "", time.Time{}, fmt.Errorf("generate CSRF token: %w", err)
	}
	token = hex.EncodeToString(raw)
	csrf = hex.EncodeToString(c)
	expires = time.Now().Add(12 * time.Hour)
	_, err = s.db.ExecContext(ctx, "INSERT INTO admin_sessions(token_hash,username,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)", hashToken(token), username, csrf, expires.UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return
}
func hashToken(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func (s *Store) Session(ctx context.Context, token string) (username, csrf string, ok bool) {
	var exp string
	if err := s.db.QueryRowContext(ctx, "SELECT username,csrf_token,expires_at FROM admin_sessions WHERE token_hash=?", hashToken(token)).Scan(&username, &csrf, &exp); err != nil {
		return "", "", false
	}
	t, e := time.Parse(time.RFC3339Nano, exp)
	if e != nil || time.Now().After(t) {
		_, _ = s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash=?", hashToken(token))
		return "", "", false
	}
	return username, csrf, true
}
func (s *Store) Logout(ctx context.Context, token string) {
	_, _ = s.db.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash=?", hashToken(token))
}
func (s *Store) Cleanup(ctx context.Context, eventDays int) error {
	if eventDays < 1 {
		eventDays = 30
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM blocked_evidence WHERE expires_at < ?", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM audit_events WHERE created_at < ?", time.Now().UTC().Add(-time.Duration(eventDays)*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		return err
	}
	// Evidence is plaintext by design. A truncating checkpoint removes deleted
	// rows from the WAL instead of leaving recoverable copies after expiry.
	var busy, remaining, checkpointed int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &remaining, &checkpointed); err != nil {
		return err
	}
	if busy != 0 || remaining != 0 {
		return fmt.Errorf("sqlite WAL truncate incomplete: busy=%d remaining=%d checkpointed=%d", busy, remaining, checkpointed)
	}
	return nil
}
func (s *Store) Overview(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	for k, q := range map[string]string{"total_requests": "SELECT count(*) FROM audit_events", "blocked_requests": "SELECT count(*) FROM audit_events WHERE outcome='block'", "audited_requests": "SELECT count(*) FROM audit_events WHERE action='audit'", "bypassed_requests": "SELECT count(*) FROM audit_events WHERE action='bypass'"} {
		var n int64
		if err := s.db.QueryRowContext(ctx, q).Scan(&n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	var asyncConfigured int64
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM ai_nodes WHERE enabled=1 AND slot IN ('async_1','async_2','async_3')").Scan(&asyncConfigured); err != nil {
		return nil, err
	}
	out["async_nodes_configured"] = asyncConfigured
	var promotions int64
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM rule_promotions").Scan(&promotions); err != nil {
		return nil, err
	}
	out["async_promotions"] = promotions
	return out, nil
}
