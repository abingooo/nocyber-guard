package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOpenAIReviewerContract(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/chat/completions" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer secret-token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"result\":\"reject\",\"confidence\":0.99,\"reason\":\"unsafe\",\"category\":\"injection\"}"}}]}`))
	}))
	defer server.Close()
	reviewer, err := NewOpenAIReviewer(OpenAIReviewerConfig{BaseURL: server.URL, APIKey: "secret-token", Model: "guard-model", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reviewer.Review(context.Background(), AIReviewRequest{Field: "instructions", Content: "untrusted text", Model: "gpt-target", Criteria: "strict"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Result != VerdictReject || result.Confidence != 0.99 || result.Model != "guard-model" {
		t.Fatalf("result = %#v", result)
	}
	if received["model"] != "guard-model" {
		t.Fatalf("model request = %#v", received["model"])
	}
	format, ok := received["response_format"].(map[string]any)
	if !ok || format["type"] != "json_schema" {
		t.Fatalf("response_format = %#v", received["response_format"])
	}
	messages, ok := received["messages"].([]any)
	if !ok || len(messages) != 2 {
		t.Fatalf("messages = %#v", received["messages"])
	}
	user := messages[1].(map[string]any)["content"].(string)
	if !strings.Contains(user, "untrusted text") || !strings.Contains(user, "gpt-target") {
		t.Fatalf("user payload = %q", user)
	}
}

func TestOpenAIReviewerFallsBackToJSONObject(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		call := calls.Add(1)
		format := body["response_format"].(map[string]any)
		if call == 1 {
			if format["type"] != "json_schema" {
				t.Errorf("first mode = %#v", format)
			}
			http.Error(w, "unsupported response format", http.StatusBadRequest)
			return
		}
		if format["type"] != "json_object" {
			t.Errorf("second mode = %#v", format)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"result\":\"pass\",\"confidence\":1,\"reason\":\"ok\",\"category\":\"benign\"}"}}]}`))
	}))
	defer server.Close()
	reviewer, err := NewOpenAIReviewer(OpenAIReviewerConfig{BaseURL: server.URL + "/v1", APIKey: "token", HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reviewer.Review(context.Background(), AIReviewRequest{Field: "input1", Content: "hello"})
	if err != nil || result.Result != VerdictPass || calls.Load() != 2 {
		t.Fatalf("result=%#v err=%v calls=%d", result, err, calls.Load())
	}
}

func TestOpenAIReviewerRejectsLooseOrInvalidContract(t *testing.T) {
	contents := []string{
		"```json\n{\"result\":\"pass\",\"confidence\":1,\"reason\":\"ok\",\"category\":\"x\"}\n```",
		`{"result":"pass","confidence":1,"reason":"ok","category":"x","extra":true}`,
		`{"result":"maybe","confidence":1,"reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":2,"reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":null,"reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":"1","reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":1,"reason":"","category":"x"}`,
		`{"result":"pass","result":"reject","confidence":1,"reason":"x","category":"x"}`,
	}
	for _, content := range contents {
		if _, err := parseStrictAIVerdict(content); !errors.Is(err, ErrAIInvalidResponse) {
			t.Errorf("parseStrictAIVerdict(%q) error=%v", content, err)
		}
	}
}

func TestOpenAIReviewerAcceptsCompatibleVerdictFormatting(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		result     Verdict
		confidence float64
	}{
		{
			name:       "markdown fence",
			content:    "```json\n{\"result\":\"pass\",\"confidence\":0.98,\"reason\":\"ok\",\"category\":\"benign\"}\n```",
			result:     VerdictPass,
			confidence: 0.98,
		},
		{
			name:       "surrounding explanation",
			content:    "Here is the verdict:\n{\"result\":\"reject\",\"confidence\":0.97,\"reason\":\"unsafe\",\"category\":\"injection\"}\nDone.",
			result:     VerdictReject,
			confidence: 0.97,
		},
		{
			name:       "case string confidence and extra metadata",
			content:    `{ "Result": " PASS ", "Confidence": "0.96", "Reason": " valid ", "Category": " benign_template ", "provider_note": "ok" }`,
			result:     VerdictPass,
			confidence: 0.96,
		},
		{
			name:       "byte order mark",
			content:    "\ufeff{\"result\":\"uncertain\",\"confidence\":0.5,\"reason\":\"unclear\",\"category\":\"unknown\"}",
			result:     VerdictUncertain,
			confidence: 0.5,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCompatibleAIVerdict(test.content)
			if err != nil {
				t.Fatal(err)
			}
			if got.Result != test.result || got.Confidence != test.confidence {
				t.Fatalf("verdict=%+v", got)
			}
		})
	}
}

func TestOpenAIReviewerCompatibleParserRejectsAmbiguousOrIncompleteVerdicts(t *testing.T) {
	contents := []string{
		`{"result":"pass","confidence":1,"reason":"ok","category":"x"} {"result":"reject","confidence":1,"reason":"no","category":"x"}`,
		`{"result":"allow","confidence":1,"reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":"95%","reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":"NaN","reason":"ok","category":"x"}`,
		`{"result":"pass","confidence":1,"reason":"ok"}`,
		`{"result":"pass","Result":"reject","confidence":1,"reason":"ok","category":"x"}`,
		"```yaml\n{\"result\":\"pass\",\"confidence\":1,\"reason\":\"ok\",\"category\":\"x\"}\n```",
	}
	for _, content := range contents {
		if _, err := parseCompatibleAIVerdict(content); !errors.Is(err, ErrAIInvalidResponse) {
			t.Errorf("parseCompatibleAIVerdict(%q) error=%v", content, err)
		}
	}
}

func TestOpenAIReviewerAcceptsTextContentBlocks(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"content":[{"type":"reasoning","text":"ignored"},{"type":"text","text":"{\"result\":\"pass\",\"confidence\":1,\"reason\":\"ok\",\"category\":\"benign\"}"}]}}]}`)
	content, err := extractOpenAIMessageContent(body)
	if err != nil {
		t.Fatal(err)
	}
	verdict, err := parseCompatibleAIVerdict(content)
	if err != nil || verdict.Result != VerdictPass {
		t.Fatalf("verdict=%+v err=%v", verdict, err)
	}
}

func TestOpenAIReviewerDoesNotFollowRedirect(t *testing.T) {
	var destinationCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		destinationCalls.Add(1)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		http.Redirect(w, request, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	reviewer, err := NewOpenAIReviewer(OpenAIReviewerConfig{BaseURL: source.URL, APIKey: "redirect-canary", HTTPClient: source.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = reviewer.Review(context.Background(), AIReviewRequest{Field: "instructions", Content: "hello"})
	if !errors.Is(err, ErrAIUnavailable) || destinationCalls.Load() != 0 {
		t.Fatalf("err=%v destinationCalls=%d", err, destinationCalls.Load())
	}
}

func TestChatCompletionsURL(t *testing.T) {
	cases := map[string]string{
		"https://example.test":                     "https://example.test/v1/chat/completions",
		"https://example.test/v1/":                 "https://example.test/v1/chat/completions",
		"https://example.test/openai":              "https://example.test/openai/v1/chat/completions",
		"https://example.test/v1/chat/completions": "https://example.test/v1/chat/completions",
	}
	for input, want := range cases {
		got, err := chatCompletionsURL(input)
		if err != nil || got != want {
			t.Errorf("chatCompletionsURL(%q)=%q,%v want %q", input, got, err, want)
		}
	}
	if _, err := chatCompletionsURL("https://token@example.test/v1?x=1"); err == nil {
		t.Fatal("URL credentials/query must be rejected")
	}
}
