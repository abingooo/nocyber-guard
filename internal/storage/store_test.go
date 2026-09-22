package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/abingooo/nocyber-guard/internal/audit"
)

func TestOpenIsIdempotentAndDataSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	masterKey := []byte("test-master-key-for-restart")

	first, err := Open(ctx, dataDir, masterKey)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}

	second, err := Open(ctx, dataDir, masterKey)
	if err != nil {
		_ = first.Close()
		t.Fatalf("repeated Open: %v", err)
	}

	var migrationCount int
	if err := second.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version=1").Scan(&migrationCount); err != nil {
		t.Fatalf("query schema migration: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration count = %d, want 1", migrationCount)
	}
	if err := second.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version=2").Scan(&migrationCount); err != nil {
		t.Fatalf("query event-contract migration: %v", err)
	}
	if migrationCount != 1 {
		t.Fatalf("event-contract migration count = %d, want 1", migrationCount)
	}
	if err := second.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version=5").Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("key-trace migration count = (%d, %v), want (1, nil)", migrationCount, err)
	}

	cfg, err := first.GetConfig(ctx, "http://initial-upstream.example")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	cfg.UpstreamURL = "http://persisted-upstream.example"
	if err := first.PutConfig(ctx, cfg, cfg.Version); err != nil {
		t.Fatalf("PutConfig: %v", err)
	}

	ruleContent := "  persisted rule\nwith exact whitespace  "
	hash := hashPlaintext(ruleContent)
	if _, err := first.AddHashWithContent(ctx, "trusted", hash, "persisted hash", ruleContent); err != nil {
		t.Fatalf("AddHash: %v", err)
	}

	if err := second.Close(); err != nil {
		_ = first.Close()
		t.Fatalf("close repeated store: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	reopened, err := Open(ctx, dataDir, masterKey)
	if err != nil {
		t.Fatalf("Open after close: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })

	restored, err := reopened.GetConfig(ctx, "http://runtime-upstream.example")
	if err != nil {
		t.Fatalf("GetConfig after restart: %v", err)
	}
	if restored.Version != 2 {
		t.Errorf("restored config version = %d, want 2", restored.Version)
	}
	if restored.UpstreamURL != "http://persisted-upstream.example" {
		t.Errorf("restored upstream = %q, want persisted value", restored.UpstreamURL)
	}
	match, found, err := reopened.LookupHash(ctx, hash)
	if err != nil {
		t.Fatalf("LookupHash after restart: %v", err)
	}
	if !found || match.Kind != "trusted" || match.Note != "persisted hash" {
		t.Fatalf("restored hash = (%+v, found=%v), want trusted persisted hash", match, found)
	}
	entries, err := reopened.ListHashes(ctx, "trusted")
	if err != nil || len(entries) != 1 || entries[0].Content != ruleContent {
		t.Fatalf("restored plaintext entries = (%+v, %v)", entries, err)
	}
}

func TestHashPlaintextValidationAndLegacyBackfill(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	content := "精确原文\n  包含空格"
	hash := hashPlaintext(content)

	if _, err := store.AddHashWithContent(ctx, "risk", strings.Repeat("f", 64), "mismatch", content); err == nil {
		t.Fatal("mismatched rule plaintext was accepted")
	}
	legacy, err := store.AddHash(ctx, "risk", hash, "legacy")
	if err != nil || legacy.Content != "" {
		t.Fatalf("legacy hash-only rule = (%+v, %v)", legacy, err)
	}
	if err := store.StoreHashContent(ctx, "risk", hash, content); err != nil {
		t.Fatalf("StoreHashContent: %v", err)
	}
	entries, err := store.ListHashes(ctx, "risk")
	if err != nil || len(entries) != 1 || entries[0].Content != content {
		t.Fatalf("backfilled rules = (%+v, %v)", entries, err)
	}
}

func TestHashContextStoresOnlyFirstMaskedKeyTrace(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	content := "rule with API key provenance"
	hash := hashPlaintext(content)
	firstFingerprint := strings.Repeat("a", 64)
	secondFingerprint := strings.Repeat("b", 64)
	if _, err := store.AddHash(ctx, "trusted", hash, "legacy"); err != nil {
		t.Fatalf("AddHash: %v", err)
	}
	if err := store.StoreHashContext(ctx, "trusted", hash, content, firstFingerprint, "sk-…A7F2"); err != nil {
		t.Fatalf("StoreHashContext: %v", err)
	}
	if err := store.StoreHashContext(ctx, "trusted", hash, content, secondFingerprint, "sk-…B8E3"); err != nil {
		t.Fatalf("second StoreHashContext: %v", err)
	}
	entries, err := store.ListHashes(ctx, "trusted")
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListHashes = (%+v, %v)", entries, err)
	}
	if entries[0].APIKeyFingerprint != firstFingerprint || entries[0].APIKeyHint != "sk-…A7F2" || entries[0].APIKeySeenAt == "" {
		t.Fatalf("stored key trace = %+v, want first source", entries[0])
	}
}

func TestRulePlaintextMigrationUpgradesV03Database(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "nocyber-guard.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.ExecContext(ctx, `
		CREATE TABLE trusted_hashes(id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
		CREATE TABLE risk_hashes(id INTEGER PRIMARY KEY AUTOINCREMENT, sha256 TEXT NOT NULL UNIQUE, label TEXT NOT NULL DEFAULT '', source TEXT NOT NULL DEFAULT 'manual', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
		CREATE TABLE review_jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, job_key TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, field_name TEXT NOT NULL, model TEXT NOT NULL DEFAULT '', sampled INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued', promotion TEXT NOT NULL DEFAULT '', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL DEFAULT '', last_error TEXT NOT NULL DEFAULT '', sample_ciphertext BLOB NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT '', completed_at TEXT NOT NULL DEFAULT '');
		INSERT INTO trusted_hashes(sha256,label,source,enabled,created_at) VALUES(?,?,?,?,?);
		INSERT INTO risk_hashes(sha256,label,source,enabled,created_at) VALUES(?,?,?,?,?)`,
		strings.Repeat("a", 64), "legacy trusted", "import", 1, time.Now().UTC().Format(time.RFC3339Nano),
		strings.Repeat("b", 64), "legacy risk", "import", 1, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("create v0.3 schema: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close v0.3 database: %v", err)
	}

	store, err := Open(ctx, dataDir, []byte("migration-master-key"))
	if err != nil {
		t.Fatalf("upgrade v0.3 database: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, kind := range []string{"trusted", "risk"} {
		entries, listErr := store.ListHashes(ctx, kind)
		if listErr != nil || len(entries) != 1 || entries[0].Content != "" {
			t.Fatalf("%s migrated rules = (%+v, %v)", kind, entries, listErr)
		}
	}
	var migrationCount int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version=4").Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("plaintext migration marker = (%d, %v), want (1, nil)", migrationCount, err)
	}
	var contentCiphertext []byte
	if err := store.db.QueryRowContext(ctx, "SELECT content_ciphertext FROM review_jobs LIMIT 1").Scan(&contentCiphertext); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("review_jobs content column probe error = %v, want no rows", err)
	}
}

func TestRulePlaintextMigrationRecoversCompleteBlockingEvidence(t *testing.T) {
	ctx := context.Background()
	store, dataDir, masterKey := openTestStore(t)
	content := "legacy blocked rule with exact plaintext"
	hash := hashPlaintext(content)
	if _, err := store.AddHash(ctx, "risk", hash, "legacy risk"); err != nil {
		t.Fatalf("AddHash: %v", err)
	}
	event := testAuditEvent("v4-backfill-event", time.Now().UTC())
	event.SHA256 = hash
	event.Decision = "block"
	event.Outcome = audit.EventOutcomeBlock
	event.Reason = audit.ReasonRiskHashMatch
	if err := store.RecordBlockedEvent(ctx, event, "instructions", content); err != nil {
		t.Fatalf("RecordBlockedEvent: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, "DELETE FROM schema_migrations WHERE version=4"); err != nil {
		t.Fatalf("remove v4 marker: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close pre-v4 database: %v", err)
	}

	reopened, err := Open(ctx, dataDir, masterKey)
	if err != nil {
		t.Fatalf("reopen with v4 migration: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	entries, err := reopened.ListHashes(ctx, "risk")
	if err != nil || len(entries) != 1 || entries[0].Content != content {
		t.Fatalf("recovered risk plaintext = (%+v, %v)", entries, err)
	}
}

func TestEventContractMigrationBackfillsLegacyDatabase(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "nocyber-guard.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	_, err = legacy.ExecContext(ctx, `CREATE TABLE audit_events(
		id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT NOT NULL, method TEXT NOT NULL,
		path TEXT NOT NULL, protocol TEXT NOT NULL, model TEXT NOT NULL, user_agent TEXT NOT NULL,
		profile_key TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, field_name TEXT NOT NULL,
		sha256 TEXT NOT NULL, prompt_bytes INTEGER NOT NULL, prompt_runes INTEGER NOT NULL,
		ai_sampled INTEGER NOT NULL, ai_result TEXT NOT NULL DEFAULT '', ai_confidence REAL NOT NULL DEFAULT 0,
		ai_reason TEXT NOT NULL DEFAULT '', ai_category TEXT NOT NULL DEFAULT '', latency_ms INTEGER NOT NULL,
		created_at TEXT NOT NULL);
		INSERT INTO audit_events(request_id,method,path,protocol,model,user_agent,profile_key,decision,reason,
			field_name,sha256,prompt_bytes,prompt_runes,ai_sampled,ai_result,ai_confidence,ai_reason,ai_category,
			latency_ms,created_at)
		VALUES('legacy-request','POST','/v1/responses','openai_responses','legacy-model','known/1','known',
			'allow','ai_timeout','instructions','',1,1,0,'',0,'legacy-free-text','legacy-category',17,?)`, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		_ = legacy.Close()
		t.Fatalf("create legacy database: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	store, err := Open(ctx, dataDir, []byte("migration-master-key"))
	if err != nil {
		t.Fatalf("migrate legacy database: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event, err := store.GetEvent(ctx, 1)
	if err != nil {
		t.Fatalf("GetEvent after migration: %v", err)
	}
	if event.Action != string(audit.EventActionAudit) || event.Outcome != string(audit.EventOutcomeFailOpen) ||
		event.AuditLatencyMS != 17 || event.LatencyMS != 17 || !event.UpstreamAccessed {
		t.Fatalf("migrated event contract = %+v", event)
	}
	var aiReason, aiCategory string
	if err := store.db.QueryRowContext(ctx, "SELECT ai_reason,ai_category FROM audit_events WHERE id=1").Scan(&aiReason, &aiCategory); err != nil || aiReason != "" || aiCategory != "" {
		t.Fatalf("legacy reviewer free text was not cleared: reason=%q category=%q err=%v", aiReason, aiCategory, err)
	}
	var migrationCount int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations WHERE version=2").Scan(&migrationCount); err != nil || migrationCount != 1 {
		t.Fatalf("event migration marker = (%d, %v), want (1, nil)", migrationCount, err)
	}

	_, err = store.db.ExecContext(ctx, `UPDATE audit_events SET
		action='bypass', outcome='allow', audit_latency_ms=101,
		ai_latency_ms=37, upstream_accessed=0
		WHERE id=1`)
	if err != nil {
		t.Fatalf("write v2 event fields: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close migrated database: %v", err)
	}

	store, err = Open(ctx, dataDir, []byte("migration-master-key"))
	if err != nil {
		t.Fatalf("reopen migrated database: %v", err)
	}
	event, err = store.GetEvent(ctx, 1)
	if err != nil {
		t.Fatalf("GetEvent after second Open: %v", err)
	}
	if event.Action != "bypass" || event.Outcome != "allow" || event.AuditLatencyMS != 101 ||
		event.AILatencyMS != 37 || event.UpstreamAccessed {
		t.Fatalf("second Open rewrote v2 event contract fields: %+v", event)
	}
}

func TestAdminCreateLoginSessionAndLogout(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)

	if err := store.EnsureAdmin(ctx, "abin", "correct password"); err != nil {
		t.Fatalf("EnsureAdmin: %v", err)
	}
	if err := store.EnsureAdmin(ctx, "replacement", "replacement password"); err != nil {
		t.Fatalf("repeated EnsureAdmin: %v", err)
	}

	if _, _, _, err := store.Login(ctx, "abin", "wrong password"); err == nil {
		t.Fatal("Login with wrong password succeeded")
	}
	if _, _, _, err := store.Login(ctx, "replacement", "replacement password"); err == nil {
		t.Fatal("repeated EnsureAdmin created a replacement administrator")
	}

	token, csrf, expires, err := store.Login(ctx, "abin", "correct password")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" || csrf == "" {
		t.Fatalf("Login returned empty credentials: token=%q csrf=%q", token, csrf)
	}
	if !expires.After(time.Now()) {
		t.Fatalf("session expiry = %s, want future time", expires)
	}

	username, sessionCSRF, ok := store.Session(ctx, token)
	if !ok || username != "abin" || sessionCSRF != csrf {
		t.Fatalf("Session = (%q, %q, %v), want (%q, %q, true)", username, sessionCSRF, ok, "abin", csrf)
	}
	if _, _, ok := store.Session(ctx, "not-a-session-token"); ok {
		t.Fatal("unknown session token was accepted")
	}

	store.Logout(ctx, token)
	if _, _, ok := store.Session(ctx, token); ok {
		t.Fatal("session remained valid after Logout")
	}
}

func TestConfigVersionUpdateAndConflict(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)

	initial, err := store.GetConfig(ctx, "http://upstream-v1.example")
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if initial.Version != 1 {
		t.Fatalf("initial version = %d, want 1", initial.Version)
	}

	updated := initial
	updated.UpstreamURL = "http://upstream-v2.example"
	updated.RequestTimeoutMS = 23000
	if err := store.PutConfig(ctx, updated, initial.Version); err != nil {
		t.Fatalf("PutConfig update: %v", err)
	}

	current, err := store.GetConfig(ctx, "http://runtime-upstream.example")
	if err != nil {
		t.Fatalf("GetConfig updated: %v", err)
	}
	if current.Version != initial.Version+1 {
		t.Errorf("updated version = %d, want %d", current.Version, initial.Version+1)
	}
	if current.UpstreamURL != updated.UpstreamURL || current.RequestTimeoutMS != updated.RequestTimeoutMS {
		t.Errorf("updated config = %+v, want persisted upstream and timeout %d", current, updated.RequestTimeoutMS)
	}

	stale := current
	stale.UpstreamURL = "http://stale-writer.example"
	err = store.PutConfig(ctx, stale, initial.Version)
	if err == nil || !strings.Contains(err.Error(), "config version conflict") {
		t.Fatalf("stale PutConfig error = %v, want config version conflict", err)
	}

	afterConflict, err := store.GetConfig(ctx, "http://runtime-upstream.example")
	if err != nil {
		t.Fatalf("GetConfig after conflict: %v", err)
	}
	if afterConflict.Version != current.Version || afterConflict.UpstreamURL != current.UpstreamURL {
		t.Fatalf("conflict changed stored config: got %+v, want %+v", afterConflict, current)
	}
}

func TestValidateConfigRejectsInvalidRuntimeValues(t *testing.T) {
	valid := defaultConfig("https://upstream.example/base")
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"mode", func(c *Config) { c.Mode = "strict" }},
		{"empty paths", func(c *Config) { c.ProtectedPaths = nil }},
		{"root path", func(c *Config) { c.ProtectedPaths = []string{"/"} }},
		{"child alias", func(c *Config) { c.ProtectedPaths = []string{"/responses/../v1/responses"} }},
		{"query path", func(c *Config) { c.ProtectedPaths = []string{"/v1/responses?x=1"} }},
		{"duplicate path", func(c *Config) { c.ProtectedPaths = []string{"/v1/responses", "/v1/responses"} }},
		{"short timeout", func(c *Config) { c.RequestTimeoutMS = 99 }},
		{"large body", func(c *Config) { c.MaxBodyBytes = 65 << 20 }},
		{"zero retention", func(c *Config) { c.EventRetentionDays = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.ProtectedPaths = append([]string(nil), valid.ProtectedPaths...)
			test.mutate(&candidate)
			if err := ValidateConfig(candidate); err == nil {
				t.Fatalf("ValidateConfig(%+v) succeeded", candidate)
			}
		})
	}
	if err := ValidateConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestSaveProfileRejectsInvalidMatcherBeforeWriting(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	_, err := store.SaveProfile(ctx, ClientProfile{
		Name: "broken regex", Enabled: true, Priority: 10,
		Matchers: []ClientMatcher{{Type: "regex", Value: "["}},
	})
	if err == nil {
		t.Fatal("SaveProfile accepted invalid regex")
	}
	profiles, listErr := store.ListProfiles(ctx)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(profiles) != 0 {
		t.Fatalf("invalid profile was persisted: %+v", profiles)
	}
}

func TestRiskHashTakesPriorityOverTrustedHash(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	hash := strings.Repeat("b", 64)

	if _, err := store.AddHash(ctx, "trusted", strings.ToUpper(hash), "trusted copy"); err != nil {
		t.Fatalf("AddHash trusted: %v", err)
	}
	if _, err := store.AddHash(ctx, "risk", hash, "risk copy"); err != nil {
		t.Fatalf("AddHash risk: %v", err)
	}

	match, found, err := store.LookupHash(ctx, strings.ToUpper(hash))
	if err != nil {
		t.Fatalf("LookupHash: %v", err)
	}
	if !found {
		t.Fatal("LookupHash did not find hash present in both tables")
	}
	if match.Kind != "risk" || match.Note != "risk copy" || match.SHA256 != hash {
		t.Fatalf("LookupHash = %+v, want risk match", match)
	}
}

func TestAIAPIKeyIsEncryptedAtRest(t *testing.T) {
	ctx := context.Background()
	store, dataDir, _ := openTestStore(t)
	apiKey := "ncg-api-key-plaintext-canary-76d417c5"
	want := AIEndpoint{
		BaseURL:        "https://reviewer.example/v1",
		Model:          "guard-reviewer",
		APIKey:         apiKey,
		TimeoutMS:      27000,
		MaxConcurrency: 7,
	}

	if err := store.SaveAIEndpoint(ctx, want); err != nil {
		t.Fatalf("SaveAIEndpoint: %v", err)
	}

	var stored []byte
	if err := store.db.QueryRowContext(ctx, "SELECT api_key FROM ai_endpoints WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("query stored API key: %v", err)
	}
	if len(stored) == 0 || bytes.Equal(stored, []byte(apiKey)) || bytes.Contains(stored, []byte(apiKey)) {
		t.Fatalf("stored API key is not encrypted: %q", stored)
	}
	assertDatabaseArtifactsExclude(t, dataDir, apiKey)

	got, err := store.GetAIEndpoint(ctx)
	if err != nil {
		t.Fatalf("GetAIEndpoint: %v", err)
	}
	if got.BaseURL != want.BaseURL || got.Model != want.Model || got.APIKey != apiKey || !got.HasAPIKey || got.TimeoutMS != want.TimeoutMS || got.MaxConcurrency != want.MaxConcurrency {
		t.Fatalf("GetAIEndpoint = %+v, want saved endpoint with decrypted key", got)
	}
}

func TestAIEndpointAllowsInitialEmptyKeyAndPreservesConfiguredKey(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	metadataOnly := AIEndpoint{BaseURL: "https://reviewer.example/v1", Model: "reviewer-a", TimeoutMS: 15000, MaxConcurrency: 16}
	if err := store.SaveAIEndpoint(ctx, metadataOnly); err != nil {
		t.Fatalf("SaveAIEndpoint without initial key: %v", err)
	}
	got, err := store.GetAIEndpoint(ctx)
	if err != nil || got.HasAPIKey || got.APIKey != "" {
		t.Fatalf("metadata-only endpoint = (%+v, %v)", got, err)
	}

	withKey := metadataOnly
	withKey.APIKey = "configured-secret-key"
	if err := store.SaveAIEndpoint(ctx, withKey); err != nil {
		t.Fatalf("SaveAIEndpoint with key: %v", err)
	}
	metadataOnly.Model = "reviewer-b"
	if err := store.SaveAIEndpoint(ctx, metadataOnly); err != nil {
		t.Fatalf("SaveAIEndpoint retaining key: %v", err)
	}
	got, err = store.GetAIEndpoint(ctx)
	if err != nil || !got.HasAPIKey || got.APIKey != withKey.APIKey || got.Model != "reviewer-b" {
		t.Fatalf("endpoint after empty-key update = (%+v, %v)", got, err)
	}
}

func TestAsyncNodesJobsVotesAndPromotion(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	node := AINode{Slot: "async_1", Name: "node one", BaseURL: "https://reviewer.example/v1", Model: "guard", APIKey: "secret", TimeoutMS: 15000, Enabled: true}
	if err := store.SaveAINode(ctx, node); err != nil {
		t.Fatalf("SaveAINode: %v", err)
	}
	nodes, err := store.ListAINodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].APIKey != "secret" || !nodes[0].HasAPIKey {
		t.Fatalf("ListAINodes=%+v err=%v", nodes, err)
	}
	original := "original promoted rule"
	hash := hashPlaintext(original)
	job, created, err := store.CreateReviewJob(ctx, hash, hash, "instructions", "model", "sample", original, false)
	if err != nil || !created || job.ID == 0 {
		t.Fatalf("CreateReviewJob=%+v created=%v err=%v", job, created, err)
	}
	jobAgain, createdAgain, err := store.CreateReviewJob(ctx, hash, hash, "instructions", "model", "sample", original, false)
	if err != nil || createdAgain || jobAgain.ID != job.ID {
		t.Fatalf("duplicate job=%+v created=%v err=%v", jobAgain, createdAgain, err)
	}
	if err := store.RecordReviewVote(ctx, ReviewVote{JobID: job.ID, NodeSlot: "async_1", Result: "reject", Confidence: .99, Reason: "risk", Category: "risk"}); err != nil {
		t.Fatalf("RecordReviewVote: %v", err)
	}
	if err := store.PromoteHash(ctx, job.ID, hash, "risk", original, "async_1:reject:.990"); err != nil {
		t.Fatalf("PromoteHash: %v", err)
	}
	match, found, err := store.LookupHash(ctx, hash)
	if err != nil || !found || match.Kind != "risk" {
		t.Fatalf("LookupHash=%+v found=%v err=%v", match, found, err)
	}
	entries, err := store.ListHashes(ctx, "risk")
	if err != nil || len(entries) != 1 || entries[0].Content != original {
		t.Fatalf("promoted plaintext rules = (%+v, %v)", entries, err)
	}
	jobs, err := store.ListReviewJobs(ctx, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListReviewJobs=%+v err=%v", jobs, err)
	}
	votes, err := store.ListReviewVotes(ctx, job.ID)
	if err != nil || len(votes) != 1 {
		t.Fatalf("ListReviewVotes=%+v err=%v", votes, err)
	}
}

func TestReviewJobClaimRetryAndStaleRecovery(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	original := "encrypted original"
	hash := hashPlaintext(original)
	job, created, err := store.CreateReviewJob(ctx, hash, hash, "instructions", "model", "encrypted sample", original, false)
	if err != nil || !created {
		t.Fatalf("CreateReviewJob = (%+v, %v, %v)", job, created, err)
	}
	claimed, err := store.ClaimReviewJob(ctx, job.ID)
	if err != nil || !claimed {
		t.Fatalf("first claim = (%v, %v)", claimed, err)
	}
	claimed, err = store.ClaimReviewJob(ctx, job.ID)
	if err != nil || claimed {
		t.Fatalf("duplicate claim = (%v, %v)", claimed, err)
	}
	old := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(ctx, "UPDATE review_jobs SET updated_at=? WHERE id=?", old, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RequeueStaleReviewJobs(ctx, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	due, err := store.ListDueReviewJobs(ctx, 10)
	if err != nil || len(due) != 1 || due[0].ID != job.ID || due[0].Status != "retry_pending" || due[0].Attempts != 1 {
		t.Fatalf("stale recovery = (%+v, %v)", due, err)
	}
	if sample, err := store.LoadReviewJobSample(ctx, job.ID); err != nil || sample != "encrypted sample" {
		t.Fatalf("recovered sample = (%q, %v)", sample, err)
	}
	if content, err := store.LoadReviewJobContent(ctx, job.ID); err != nil || content != original {
		t.Fatalf("recovered original = (%q, %v)", content, err)
	}
}

func TestBlockedEvidenceIsPlaintextOnlyInEvidenceRow(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	plaintext := "blocked-evidence-plaintext-canary-ef90d2d1"
	event := testAuditEvent("blocked-evidence-event", time.Now().UTC())
	event.Decision = "block"
	event.Reason = audit.ReasonAIReject

	if err := store.RecordBlockedEvent(ctx, event, "instructions", plaintext); err != nil {
		t.Fatalf("RecordBlockedEvent: %v", err)
	}

	var eventID int64
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM audit_events WHERE request_id=?", event.RequestID).Scan(&eventID); err != nil {
		t.Fatalf("query blocked event id: %v", err)
	}
	var stored []byte
	if err := store.db.QueryRowContext(ctx, "SELECT content FROM blocked_evidence WHERE event_id=?", eventID).Scan(&stored); err != nil {
		t.Fatalf("query stored evidence: %v", err)
	}
	if !bytes.Equal(stored, []byte(plaintext)) {
		t.Fatalf("stored evidence = %q, want selected plaintext", stored)
	}
	var leaked int
	pattern := "%" + plaintext + "%"
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE request_id LIKE ? OR model LIKE ? OR user_agent LIKE ? OR ai_reason LIKE ?", pattern, pattern, pattern, pattern).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("plaintext leaked into ordinary event metadata")
	}

	evidence, err := store.GetEvidence(ctx, eventID)
	if err != nil {
		t.Fatalf("GetEvidence: %v", err)
	}
	if evidence.EventID != eventID || evidence.FieldName != "instructions" || evidence.Content != plaintext || evidence.Partial {
		t.Fatalf("GetEvidence = %+v, want complete plaintext evidence", evidence)
	}
}

func TestCleanupRemovesExpiredEvidenceAndOldEvents(t *testing.T) {
	ctx := context.Background()
	store, dataDir, _ := openTestStore(t)
	now := time.Now().UTC()
	evidenceCanary := "expired-evidence-plaintext-canary-6b87fb87"

	oldEvent := testAuditEvent("old-event", now.Add(-48*time.Hour))
	if err := store.RecordAuditEvent(ctx, oldEvent); err != nil {
		t.Fatalf("RecordAuditEvent old: %v", err)
	}
	recentEvent := testAuditEvent("recent-event", now)
	if err := store.RecordAuditEvent(ctx, recentEvent); err != nil {
		t.Fatalf("RecordAuditEvent recent: %v", err)
	}
	blockedEvent := testAuditEvent("expired-evidence-event", now)
	blockedEvent.Decision = "block"
	blockedEvent.Reason = audit.ReasonRiskHashMatch
	if err := store.RecordBlockedEvent(ctx, blockedEvent, "instructions", evidenceCanary); err != nil {
		t.Fatalf("RecordBlockedEvent: %v", err)
	}

	var blockedEventID int64
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM audit_events WHERE request_id=?", blockedEvent.RequestID).Scan(&blockedEventID); err != nil {
		t.Fatalf("query blocked event id: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE blocked_evidence SET expires_at=? WHERE event_id=?", now.Add(-time.Hour).Format(time.RFC3339Nano), blockedEventID); err != nil {
		t.Fatalf("expire blocked evidence: %v", err)
	}

	if err := store.Cleanup(ctx, 1); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	assertRequestCount(t, store, oldEvent.RequestID, 0)
	assertRequestCount(t, store, recentEvent.RequestID, 1)
	assertRequestCount(t, store, blockedEvent.RequestID, 1)

	var evidenceCount int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM blocked_evidence WHERE event_id=?", blockedEventID).Scan(&evidenceCount); err != nil {
		t.Fatalf("count expired evidence: %v", err)
	}
	if evidenceCount != 0 {
		t.Fatalf("expired evidence count = %d, want 0", evidenceCount)
	}
	if _, err := store.GetEvidence(ctx, blockedEventID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("GetEvidence after Cleanup error = %v, want sql.ErrNoRows", err)
	}
	assertDatabaseArtifactsExclude(t, dataDir, evidenceCanary)
}

func TestSQLitePragmasApplyToEveryConnection(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	connections := make([]*sql.Conn, 0, 8)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()

	for i := 0; i < 8; i++ {
		connection, err := store.db.Conn(ctx)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		connections = append(connections, connection)
		var busyTimeout, foreignKeys, secureDelete, synchronous int
		var journalMode string
		for query, destination := range map[string]any{
			"PRAGMA busy_timeout":  &busyTimeout,
			"PRAGMA foreign_keys":  &foreignKeys,
			"PRAGMA secure_delete": &secureDelete,
			"PRAGMA synchronous":   &synchronous,
			"PRAGMA journal_mode":  &journalMode,
		} {
			if err := connection.QueryRowContext(ctx, query).Scan(destination); err != nil {
				t.Fatalf("connection %d %s: %v", i, query, err)
			}
		}
		if busyTimeout != 5000 || foreignKeys != 1 || secureDelete != 1 || synchronous != 1 || !strings.EqualFold(journalMode, "wal") {
			t.Fatalf("connection %d pragmas = busy:%d fk:%d secure:%d sync:%d journal:%q", i, busyTimeout, foreignKeys, secureDelete, synchronous, journalMode)
		}
	}
}

func TestEventContractAndReviewerFreeTextIsNotPersisted(t *testing.T) {
	ctx := context.Background()
	store, dataDir, _ := openTestStore(t)
	canary := "ordinary-event-must-not-contain-prompt-canary-83c1"
	event := testAuditEvent("event-contract", time.Now().UTC())
	event.Reason = audit.ReasonAIUnavailable
	event.AuditLatency = 41 * time.Millisecond
	event.AILatency = 31 * time.Millisecond
	event.Latency = 0
	event.AIVerdict = &audit.AIVerdict{Result: audit.VerdictUncertain, Confidence: 0.42, Reason: canary, Category: canary}

	if err := store.RecordAuditEvent(ctx, event); err != nil {
		t.Fatalf("RecordAuditEvent: %v", err)
	}
	items, total, err := store.ListEvents(ctx, 1, 20, "", "")
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("ListEvents = (%+v, %d, %v), want one event", items, total, err)
	}
	got := items[0]
	if got.Path != event.Path || got.Action != string(audit.EventActionAudit) || got.Outcome != string(audit.EventOutcomeFailOpen) ||
		got.AuditLatencyMS != 41 || got.AILatencyMS != 31 || got.LatencyMS != 41 || !got.UpstreamAccessed {
		t.Fatalf("event contract = %+v", got)
	}
	detail, err := store.GetEvent(ctx, got.ID)
	if err != nil || detail != got {
		t.Fatalf("GetEvent = (%+v, %v), want %+v", detail, err, got)
	}
	var aiReason, aiCategory string
	if err := store.db.QueryRowContext(ctx, "SELECT ai_reason,ai_category FROM audit_events WHERE id=?", got.ID).Scan(&aiReason, &aiCategory); err != nil {
		t.Fatalf("read reviewer free text: %v", err)
	}
	if aiReason != "" || aiCategory != "" {
		t.Fatalf("reviewer free text persisted: reason=%q category=%q", aiReason, aiCategory)
	}
	assertDatabaseArtifactsExclude(t, dataDir, canary)
}

func TestEventPersistsMaskedAPIKeyTraceAndSupportsSearch(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	event := testAuditEvent("key-trace-event", time.Now().UTC())
	event.APIKeyFingerprint = strings.Repeat("d", 64)
	event.APIKeyHint = "sk-…9F2A"
	if err := store.RecordAuditEvent(ctx, event); err != nil {
		t.Fatalf("RecordAuditEvent: %v", err)
	}
	items, total, err := store.ListEvents(ctx, 1, 20, "", "9F2A")
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("ListEvents key search = (%+v, %d, %v)", items, total, err)
	}
	if items[0].APIKeyFingerprint != event.APIKeyFingerprint || items[0].APIKeyHint != event.APIKeyHint {
		t.Fatalf("event key trace = %+v", items[0])
	}
	detail, err := store.GetEvent(ctx, items[0].ID)
	if err != nil || detail.APIKeyFingerprint != event.APIKeyFingerprint || detail.APIKeyHint != event.APIKeyHint {
		t.Fatalf("GetEvent key trace = (%+v, %v)", detail, err)
	}
}

func TestListEventsFiltersKeepEvidencePlaceholderOrdering(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)

	allowed := testAuditEvent("filtered-allow", time.Now().UTC())
	if err := store.RecordAuditEvent(ctx, allowed); err != nil {
		t.Fatalf("RecordAuditEvent allowed: %v", err)
	}
	blocked := testAuditEvent("filtered-block", time.Now().UTC())
	blocked.Decision = "block"
	blocked.Reason = audit.ReasonRiskHashMatch
	if err := store.RecordBlockedEvent(ctx, blocked, "instructions", "filtered evidence"); err != nil {
		t.Fatalf("RecordBlockedEvent blocked: %v", err)
	}

	items, total, err := store.ListEvents(ctx, 1, 20, "block", "filtered-block")
	if err != nil {
		t.Fatalf("ListEvents with filters: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].RequestID != blocked.RequestID || !items[0].EvidenceAvailable {
		t.Fatalf("filtered events = (%+v, %d), want the blocked event with evidence", items, total)
	}
}

func TestListEventsFilteredUsesInclusiveFromAndExclusiveTo(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	for _, item := range []struct {
		id string
		at time.Time
	}{
		{"before-range", time.Date(2026, 9, 9, 23, 59, 59, 999999999, time.UTC)},
		{"at-start", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)},
		{"inside-range", time.Date(2026, 9, 10, 12, 30, 0, 0, time.UTC)},
		{"at-end", time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)},
	} {
		event := testAuditEvent(item.id, item.at)
		if err := store.RecordAuditEvent(ctx, event); err != nil {
			t.Fatalf("RecordAuditEvent(%s): %v", item.id, err)
		}
	}
	items, total, err := store.ListEventsFiltered(ctx, 1, 20, EventFilter{
		From: time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("ListEventsFiltered: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("filtered events = (%d, %+v), want 2", total, items)
	}
	if items[0].RequestID != "inside-range" || items[1].RequestID != "at-start" {
		t.Fatalf("filtered order = [%s, %s], want inside-range, at-start", items[0].RequestID, items[1].RequestID)
	}
	if _, _, err := store.ListEventsFiltered(ctx, 1, 20, EventFilter{
		From: time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("reversed event range was accepted")
	}
}

func TestDeleteEventsRemovesEvidenceWithoutTouchingRules(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	if _, err := store.AddHash(ctx, "trusted", strings.Repeat("a", 64), "keep-rule"); err != nil {
		t.Fatalf("AddHash: %v", err)
	}

	old := testAuditEvent("cleanup-old", time.Date(2026, 9, 9, 23, 59, 59, 0, time.UTC))
	old.Decision = "block"
	old.Reason = audit.ReasonRiskHashMatch
	if err := store.RecordBlockedEvent(ctx, old, "instructions", "cleanup evidence"); err != nil {
		t.Fatalf("RecordBlockedEvent: %v", err)
	}
	for _, item := range []struct {
		id string
		at time.Time
	}{
		{"cleanup-boundary", time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)},
		{"cleanup-new", time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)},
	} {
		if err := store.RecordAuditEvent(ctx, testAuditEvent(item.id, item.at)); err != nil {
			t.Fatalf("RecordAuditEvent(%s): %v", item.id, err)
		}
	}

	before := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	deleted, err := store.DeleteEventsBefore(ctx, &before)
	if err != nil {
		t.Fatalf("DeleteEventsBefore: %v", err)
	}
	if deleted.DeletedEvents != 1 || deleted.DeletedEvidence != 1 {
		t.Fatalf("DeleteEventsBefore result = %+v, want 1 event and 1 evidence", deleted)
	}
	items, total, err := store.ListEvents(ctx, 1, 20, "", "")
	if err != nil || total != 2 || len(items) != 2 || items[0].RequestID != "cleanup-new" || items[1].RequestID != "cleanup-boundary" {
		t.Fatalf("remaining events = (%+v, %d, %v)", items, total, err)
	}
	var evidenceCount int
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM blocked_evidence").Scan(&evidenceCount); err != nil || evidenceCount != 0 {
		t.Fatalf("evidence count = (%d, %v), want 0", evidenceCount, err)
	}

	boundaryID := items[1].ID
	deleted, err = store.DeleteEvent(ctx, boundaryID)
	if err != nil || deleted.DeletedEvents != 1 {
		t.Fatalf("DeleteEvent = (%+v, %v), want one event", deleted, err)
	}
	deleted, err = store.DeleteEventsBefore(ctx, nil)
	if err != nil || deleted.DeletedEvents != 1 {
		t.Fatalf("DeleteEventsBefore(all) = (%+v, %v), want one event", deleted, err)
	}
	if rules, err := store.ListHashes(ctx, "trusted"); err != nil || len(rules) != 1 || rules[0].Label != "keep-rule" {
		t.Fatalf("trusted rules changed by event cleanup: (%+v, %v)", rules, err)
	}
}

func TestExpiredEvidenceIsNotAdvertisedBeforeCleanup(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	event := testAuditEvent("expired-but-not-cleaned", time.Now().UTC())
	event.Decision = "block"
	event.Reason = audit.ReasonRiskHashMatch
	if err := store.RecordBlockedEvent(ctx, event, "instructions", "evidence"); err != nil {
		t.Fatalf("RecordBlockedEvent: %v", err)
	}
	var id int64
	if err := store.db.QueryRowContext(ctx, "SELECT id FROM audit_events WHERE request_id=?", event.RequestID).Scan(&id); err != nil {
		t.Fatalf("event id: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE blocked_evidence SET expires_at=? WHERE event_id=?", time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano), id); err != nil {
		t.Fatalf("expire evidence: %v", err)
	}
	items, _, err := store.ListEvents(ctx, 1, 20, "", "")
	if err != nil || len(items) != 1 || items[0].EvidenceAvailable {
		t.Fatalf("ListEvents expired evidence = (%+v, %v)", items, err)
	}
	detail, err := store.GetEvent(ctx, id)
	if err != nil || detail.EvidenceAvailable {
		t.Fatalf("GetEvent expired evidence = (%+v, %v)", detail, err)
	}
}

func TestOverviewUsesRecordedHourlyAndLatencyData(t *testing.T) {
	ctx := context.Background()
	store, _, _ := openTestStore(t)
	event := testAuditEvent("overview-real-data", time.Now().UTC())
	event.Decision = "block"
	event.Action = audit.EventActionAudit
	event.Outcome = audit.EventOutcomeBlock
	event.AuditLatency = 27 * time.Millisecond
	event.AILatency = 19 * time.Millisecond
	if err := store.RecordAuditEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats["total_requests"] != int64(1) || stats["blocked_requests"] != int64(1) || stats["avg_audit_latency_ms"] != int64(27) || stats["avg_ai_latency_ms"] != int64(19) {
		t.Fatalf("unexpected overview stats: %+v", stats)
	}
	if got := reflect.ValueOf(stats["hourly"]).Len(); got != 12 {
		t.Fatalf("hourly buckets = %d, want 12", got)
	}
}

func TestBoundedEvidencePreservesUTF8AndByteLimit(t *testing.T) {
	original := strings.Repeat("界🙂", 80)
	got, partial := boundedEvidence(original, 97)
	if !partial || !utf8.ValidString(got) || len([]byte(got)) > 97 {
		t.Fatalf("bounded evidence partial=%v valid=%v bytes=%d", partial, utf8.ValidString(got), len([]byte(got)))
	}
	if !strings.Contains(got, "[... evidence truncated ...]") {
		t.Fatalf("bounded evidence lacks truncation marker: %q", got)
	}
	if complete, partial := boundedEvidence("完整内容", 64); partial || complete != "完整内容" {
		t.Fatalf("complete evidence = (%q, %v)", complete, partial)
	}
}

func openTestStore(t *testing.T) (*Store, string, []byte) {
	t.Helper()
	ctx := context.Background()
	dataDir := t.TempDir()
	masterKey := []byte("test-master-key-2cf837fd")
	store, err := Open(ctx, dataDir, masterKey)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, dataDir, masterKey
}

func testAuditEvent(requestID string, createdAt time.Time) audit.Event {
	return audit.Event{
		RequestID:   requestID,
		Method:      "POST",
		Path:        "/v1/responses",
		Protocol:    audit.ProtocolResponses,
		Model:       "test-model",
		UserAgent:   "codex_cli_rs/1.0",
		ProfileKey:  "codex_cli_rs",
		Decision:    "allow",
		Reason:      audit.ReasonAIPass,
		Field:       "instructions",
		SHA256:      strings.Repeat("c", 64),
		PromptBytes: 42,
		PromptRunes: 42,
		AISampled:   false,
		Latency:     12 * time.Millisecond,
		CreatedAt:   createdAt,
	}
}

func assertDatabaseArtifactsExclude(t *testing.T, dataDir, plaintext string) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dataDir, "nocyber-guard.db*"))
	if err != nil {
		t.Fatalf("glob database artifacts: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no database artifacts found")
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read database artifact %s: %v", filepath.Base(path), err)
		}
		if bytes.Contains(contents, []byte(plaintext)) {
			t.Errorf("database artifact %s contains plaintext secret", filepath.Base(path))
		}
	}
}

func assertRequestCount(t *testing.T, store *Store, requestID string, want int) {
	t.Helper()
	var got int
	if err := store.db.QueryRow("SELECT count(*) FROM audit_events WHERE request_id=?", requestID).Scan(&got); err != nil {
		t.Fatalf("count request %q: %v", requestID, err)
	}
	if got != want {
		t.Fatalf("request %q count = %d, want %d", requestID, got, want)
	}
}
