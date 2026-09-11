package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestParseResponsesInstructionsPrecedesInput1(t *testing.T) {
	body := []byte(`{"instructions":"  system 😀  ","input":[{"content":"ignored-0"},{"content":[{"type":"input_text","text":"ignored-1"}]}]}`)
	parsed, err := ParseResponses(context.Background(), body, 0)
	if err != nil {
		t.Fatalf("ParseResponses() error = %v", err)
	}
	if parsed.SelectedName != "instructions" || parsed.Selected.Text != "  system 😀  " {
		t.Fatalf("selected = %#v, want exact instructions", parsed.Selected)
	}
	want := sha256.Sum256([]byte("  system 😀  "))
	if parsed.Selected.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("hash = %s, want exact source hash", parsed.Selected.SHA256)
	}
}

func TestParseResponsesOnlyInputOneAndInputText(t *testing.T) {
	body := []byte(`{"input":[{"content":[{"type":"input_text","text":"input-zero"}]},{"role":"user","content":[{"type":"input_text","text":"one-a"},{"type":"input_text","text":"one-b"}]},{"content":[{"type":"input_text","text":"input-two"}]}]}`)
	parsed, err := ParseResponses(context.Background(), body, 0)
	if err != nil {
		t.Fatalf("ParseResponses() error = %v", err)
	}
	if parsed.SelectedName != "input1" || parsed.Selected.Text != "one-aone-b" {
		t.Fatalf("selected = %#v, want concatenated input[1] text blocks", parsed.Selected)
	}
}

func TestParseResponsesInputOneInvalidBlockDoesNotPartiallySelect(t *testing.T) {
	for _, body := range []string{
		`{"input":[{}, {"content":[{"type":"input_text","text":"ok"},{"type":"image_url","url":"x"}]}]}`,
		`{"input":[{}, {"content":[{"type":"input_text","text":1}]}]}`,
		`{"input":[{}, "text"]}`,
	} {
		parsed, err := ParseResponses(context.Background(), []byte(body), 0)
		if err != nil {
			t.Fatalf("ParseResponses(%s) error = %v", body, err)
		}
		if parsed.SelectedName != "" {
			t.Fatalf("selected %q for invalid input block %s", parsed.SelectedName, body)
		}
	}
}

func TestParseResponsesRejectsDuplicateKeysAndTrailingJSON(t *testing.T) {
	cases := []string{
		`{"instructions":"one","instructions":"two"}`,
		`{"input":[{}, {"content":[{"type":"input_text","text":"x","text":"y"}]}]}`,
		`{"other":{"nested":1,"nested":2}}`,
		`{"instructions":"x"} {"instructions":"y"}`,
	}
	for _, body := range cases {
		if _, err := ParseResponses(context.Background(), []byte(body), 0); err == nil {
			t.Errorf("ParseResponses(%s) error = nil, want malformed JSON", body)
		} else if !errors.Is(err, ErrInvalidJSON) && !errors.Is(err, ErrDuplicateKey) {
			t.Errorf("ParseResponses(%s) error = %v, want JSON error", body, err)
		}
	}
}

func TestParseResponsesDepthAndCancellation(t *testing.T) {
	deep := strings.Repeat(`[`, 20) + `"x"` + strings.Repeat(`]`, 20)
	if _, err := ParseResponses(context.Background(), []byte(`{"other":`+deep+`}`), 4); !errors.Is(err, ErrJSONDepth) {
		t.Fatalf("depth error = %v, want ErrJSONDepth", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseResponses(ctx, []byte(`{"instructions":"x"}`), 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v, want context.Canceled", err)
	}
}

func TestPrepareAISampleRuneSafe(t *testing.T) {
	field := newTextField("instructions", "你好😀"+strings.Repeat("a", 20)+"尾")
	sampled := PrepareAISample(field, 8)
	if !sampled.AISampled || !strings.Contains(sampled.AISample, sampleSeparator) {
		t.Fatalf("sample = %q, sampled = %v", sampled.AISample, sampled.AISampled)
	}
	if !strings.Contains(sampled.AISample, "你好😀") || !strings.Contains(sampled.AISample, "尾") {
		t.Fatalf("sample did not preserve rune-safe head/tail: %q", sampled.AISample)
	}
	if sampled.SHA256 != field.SHA256 || sampled.Text != field.Text {
		t.Fatal("sampling changed source or hash")
	}
}

func TestParseResponsesExtractsBoundedModelMetadata(t *testing.T) {
	parsed, err := ParseResponses(context.Background(), []byte(`{"model":"gpt-5.6","instructions":"x"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Model != "gpt-5.6" {
		t.Fatalf("model = %q", parsed.Model)
	}

	parsed, err = ParseResponses(context.Background(), []byte(`{"model":"bad\nmodel","instructions":"x"}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Model != "" {
		t.Fatalf("control-bearing model was retained: %q", parsed.Model)
	}
}
