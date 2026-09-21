package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abingooo/nocyber-guard/internal/audit"
	"github.com/abingooo/nocyber-guard/internal/storage"
)

func TestClientIPRejectsSpoofedForwardedPrefix(t *testing.T) {
	rt := &runtime{trustedProxies: parseTrustedCIDRs([]string{"127.0.0.0/8", "10.0.0.0/8"})}
	adapter := auditorAdapter{runtime: rt}
	req := httptest.NewRequest("GET", "http://guard.example/", nil)
	req.RemoteAddr = "127.0.0.1:43210"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 198.51.100.8, 10.1.2.3")

	if got := adapter.clientIP(req); got != "198.51.100.8" {
		t.Fatalf("clientIP = %q, want nearest untrusted address", got)
	}
}

func TestClientIPIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	rt := &runtime{trustedProxies: parseTrustedCIDRs([]string{"127.0.0.0/8"})}
	adapter := auditorAdapter{runtime: rt}
	req := httptest.NewRequest("GET", "http://guard.example/", nil)
	req.RemoteAddr = "192.0.2.10:43210"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	if got := adapter.clientIP(req); got != "192.0.2.10" {
		t.Fatalf("clientIP = %q, want direct peer", got)
	}
}

func TestAuditorAdapterPinsOneRuntimeGenerationPerRequest(t *testing.T) {
	first := &runtimeState{enabled: true, paths: map[string]struct{}{`/v1/responses`: {}}, auditBodyLimit: 1024}
	second := &runtimeState{enabled: true, paths: map[string]struct{}{`/other`: {}}, auditBodyLimit: 2048}
	rt := &runtime{}
	rt.state.Store(first)
	adapter := auditorAdapter{runtime: rt}
	req := httptest.NewRequest(http.MethodPost, "http://guard.example/v1/responses", nil)

	if !adapter.ShouldAudit(req) {
		t.Fatal("first generation should audit request")
	}
	rt.state.Store(second)
	if got := adapter.AuditBodyLimit(req); got != 1024 {
		t.Fatalf("body limit = %d, want pinned first-generation limit", got)
	}
	if got := adapter.requestState(req, false); got != first {
		t.Fatal("request switched runtime generations")
	}
}

func TestAuditorAdapterDisabledDoesNotReadProtectedBody(t *testing.T) {
	rt := &runtime{}
	rt.state.Store(&runtimeState{enabled: false, paths: map[string]struct{}{`/v1/responses`: {}}, auditBodyLimit: audit.DefaultMaxBodyBytes})
	adapter := auditorAdapter{runtime: rt}
	req := httptest.NewRequest(http.MethodPost, "http://guard.example/v1/responses", nil)
	if adapter.ShouldAudit(req) {
		t.Fatal("disabled audit runtime selected protected body")
	}
}

func TestAsyncRuntimeRetriesAndRecoversPersistedJob(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ruleContent := "persisted exact rule content"
	digest := sha256.Sum256([]byte(ruleContent))
	hash := hex.EncodeToString(digest[:])
	job := asyncReviewJob{Hash: hash, Field: "instructions", Content: "persisted review sample", RuleContent: ruleContent, Model: "test-model"}

	firstStore, err := storage.Open(ctx, dataDir, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	firstRuntime := newAsyncRuntime(firstStore, logger)
	failingNodes := make([]audit.AsyncNodeReviewer, 0, 3)
	for i := 1; i <= 3; i++ {
		failingNodes = append(failingNodes, audit.AsyncNodeReviewer{
			Slot: "async_" + string(rune('0'+i)),
			Reviewer: audit.ReviewerFunc(func(context.Context, audit.AIReviewRequest) (audit.AIVerdict, error) {
				return audit.AIVerdict{}, errors.New("reviewer timeout")
			}),
		})
	}
	firstRuntime.setNodes(failingNodes)
	firstRuntime.process(job)

	jobs, err := firstStore.ListReviewJobs(ctx, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("jobs after failed attempt = (%+v, %v)", jobs, err)
	}
	if jobs[0].Status != "retry_pending" || jobs[0].Attempts != 1 {
		t.Fatalf("failed attempt status = %+v, want retry_pending attempt 1", jobs[0])
	}
	if sample, err := firstStore.LoadReviewJobSample(ctx, jobs[0].ID); err != nil || sample != job.Content {
		t.Fatalf("persisted sample = (%q, %v)", sample, err)
	}
	if content, err := firstStore.LoadReviewJobContent(ctx, jobs[0].ID); err != nil || content != job.RuleContent {
		t.Fatalf("persisted rule content = (%q, %v)", content, err)
	}
	if err := firstStore.ScheduleReviewRetry(ctx, jobs[0].ID, "test_retry", time.Second); err != nil {
		t.Fatal(err)
	}
	if err := firstStore.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)

	secondStore, err := storage.Open(ctx, dataDir, masterKey)
	if err != nil {
		t.Fatal(err)
	}
	secondRuntime := newAsyncRuntime(secondStore, logger)
	secondRuntime.setNodes([]audit.AsyncNodeReviewer{
		{Slot: "async_1", Reviewer: fixedVerdictReviewer(audit.VerdictPass)},
		{Slot: "async_2", Reviewer: fixedVerdictReviewer(audit.VerdictPass)},
		{Slot: "async_3", Reviewer: audit.ReviewerFunc(func(context.Context, audit.AIReviewRequest) (audit.AIVerdict, error) {
			return audit.AIVerdict{}, errors.New("third node unavailable")
		})},
	})
	secondRuntime.start()
	defer func() {
		secondRuntime.close()
		_ = secondStore.Close()
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err = secondStore.ListReviewJobs(ctx, 10)
		if err == nil && len(jobs) == 1 && jobs[0].Status == "promoted" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(jobs) != 1 || jobs[0].Status != "promoted" || jobs[0].Promotion != "trusted" || jobs[0].Attempts != 2 {
		t.Fatalf("recovered job = %+v, want trusted promotion on attempt 2", jobs)
	}
	match, found, err := secondStore.LookupHash(ctx, hash)
	if err != nil || !found || match.Kind != "trusted" {
		t.Fatalf("recovered promotion = (%+v, %v, %v)", match, found, err)
	}
	entries, err := secondStore.ListHashes(ctx, "trusted")
	if err != nil || len(entries) != 1 || entries[0].Content != ruleContent {
		t.Fatalf("recovered promotion plaintext = (%+v, %v)", entries, err)
	}
}

func fixedVerdictReviewer(result audit.Verdict) audit.Reviewer {
	return audit.ReviewerFunc(func(context.Context, audit.AIReviewRequest) (audit.AIVerdict, error) {
		return audit.AIVerdict{Result: result, Confidence: .99, Reason: "test", Category: "test"}, nil
	})
}
