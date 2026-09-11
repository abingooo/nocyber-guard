package config

import (
	"net/url"
	"strings"
	"testing"
)

func TestValidateEndpointAgainstListeners(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		listeners []string
		wantLoop  bool
	}{
		{name: "wildcard IPv4 catches localhost", endpoint: "http://localhost:8080", listeners: []string{"0.0.0.0:8080"}, wantLoop: true},
		{name: "empty host catches loopback", endpoint: "http://127.0.0.1:8080", listeners: []string{":8080"}, wantLoop: true},
		{name: "wildcard IPv6 catches IPv6 loopback", endpoint: "http://[::1]:8080", listeners: []string{"[::]:8080"}, wantLoop: true},
		{name: "loopback aliases match", endpoint: "http://localhost:8080", listeners: []string{"127.0.0.1:8080"}, wantLoop: true},
		{name: "same explicit host matches", endpoint: "http://10.20.30.40:8080/base", listeners: []string{"10.20.30.40:8080"}, wantLoop: true},
		{name: "unspecified endpoint is local", endpoint: "http://0.0.0.0:8080", listeners: []string{"127.0.0.1:8080"}, wantLoop: true},
		{name: "http default port matches service", endpoint: "http://localhost/path", listeners: []string{"localhost:http"}, wantLoop: true},
		{name: "https default port", endpoint: "https://localhost/path", listeners: []string{"localhost:443"}, wantLoop: true},
		{name: "admin listener also checked", endpoint: "http://127.0.0.1:9090", listeners: []string{":8080", "localhost:9090"}, wantLoop: true},
		{name: "different port", endpoint: "http://localhost:8081", listeners: []string{":8080"}},
		{name: "external host on wildcard port", endpoint: "http://upstream.example:8080", listeners: []string{":8080"}},
		{name: "external address on wildcard port", endpoint: "http://192.0.2.10:8080", listeners: []string{":8080"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, err := url.Parse(tc.endpoint)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateEndpointAgainstListeners(endpoint, tc.listeners...)
			if tc.wantLoop && err == nil {
				t.Fatal("expected loop validation error")
			}
			if !tc.wantLoop && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateEndpointAgainstListenersRejectsInvalidInputs(t *testing.T) {
	if err := ValidateEndpointAgainstListeners(nil, ":8080"); err == nil {
		t.Fatal("nil endpoint was accepted")
	}
	unsupported, _ := url.Parse("ftp://upstream.example/resource")
	if err := ValidateEndpointAgainstListeners(unsupported, ":8080"); err == nil {
		t.Fatal("unsupported endpoint scheme was accepted")
	}
	valid, _ := url.Parse("http://upstream.example")
	if err := ValidateEndpointAgainstListeners(valid, "not-a-listener"); err == nil {
		t.Fatal("invalid listener address was accepted")
	}
}

func TestLoadRejectsUpstreamPointingAtDataListener(t *testing.T) {
	t.Setenv("NCG_UPSTREAM_URL", "http://localhost:18081")
	t.Setenv("NCG_LISTEN_ADDR", "127.0.0.1:18081")
	t.Setenv("NCG_ADMIN_LISTEN_ADDR", "127.0.0.1:19090")
	t.Setenv("NCG_DATA_DIR", t.TempDir())
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "points back to listener") {
		t.Fatalf("Load error = %v, want proxy loop rejection", err)
	}
}

func TestLoadRejectsCredentialsQueryAndFragmentInUpstreamURL(t *testing.T) {
	for _, raw := range []string{
		"http://admin:supersecret@upstream.example:18085",
		"http://upstream.example:18085?token=supersecret",
		"http://upstream.example:18085/#supersecret",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("NCG_UPSTREAM_URL", raw)
			t.Setenv("NCG_LISTEN_ADDR", "127.0.0.1:18081")
			t.Setenv("NCG_ADMIN_LISTEN_ADDR", "127.0.0.1:19090")
			t.Setenv("NCG_DATA_DIR", t.TempDir())
			_, err := Load()
			if err == nil {
				t.Fatal("expected invalid upstream URL error")
			}
			if strings.Contains(err.Error(), "supersecret") {
				t.Fatalf("configuration error leaked URL secret: %v", err)
			}
		})
	}
}
