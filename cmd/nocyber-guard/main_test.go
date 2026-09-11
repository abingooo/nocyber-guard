package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abingooo/nocyber-guard/internal/audit"
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
