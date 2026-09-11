package audit

import "testing"

func TestProfileMatcherPriorityAndUnknownBypass(t *testing.T) {
	matcher, err := NewProfileMatcher([]ClientProfile{
		{Key: "later", Name: "later", Priority: 20, Enabled: true, Matchers: []Matcher{{Type: "prefix", Value: "tool/"}}},
		{Key: "first", Name: "first", Priority: 10, Enabled: true, Matchers: []Matcher{{Type: "regex", Value: `^tool/\d+`, CaseSensitive: false}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := matcher.Match("TOOL/123")
	if !ok || profile.Key != "first" {
		t.Fatalf("profile = %#v, ok = %v, want first", profile, ok)
	}
	if _, ok := matcher.Match(""); ok {
		t.Fatal("empty User-Agent must bypass")
	}
	if _, ok := matcher.Match("unmatched/1"); ok {
		t.Fatal("unmatched User-Agent must bypass")
	}
}

func TestProfileMatcherExact(t *testing.T) {
	matcher, err := NewProfileMatcher([]ClientProfile{{
		Key: "desktop", Name: "Desktop", Enabled: true,
		Matchers: []Matcher{{Type: "exact", Value: "Codex Desktop/1.0", CaseSensitive: false}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if profile, ok := matcher.Match("codex desktop/1.0"); !ok || profile.Key != "desktop" {
		t.Fatalf("exact match profile=%#v ok=%v", profile, ok)
	}
	if _, ok := matcher.Match("codex desktop/1.0 extra"); ok {
		t.Fatal("exact matcher accepted a suffix")
	}
}

func TestDefaultProfilesExcludeOpenCode(t *testing.T) {
	matcher, err := NewProfileMatcher(DefaultClientProfiles())
	if err != nil {
		t.Fatal(err)
	}
	for _, userAgent := range []string{"codex_cli_rs/0.1", "Codex Desktop/1.0", "codex_vscode/0.1"} {
		if _, ok := matcher.Match(userAgent); !ok {
			t.Errorf("default profile did not match %q", userAgent)
		}
	}
	if _, ok := matcher.Match("opencode/1.0"); ok {
		t.Fatal("OpenCode must bypass by default in v0.1")
	}
}

func TestProfileMatcherValidation(t *testing.T) {
	for _, profiles := range [][]ClientProfile{
		{{Key: "Bad-Key", Name: "x", Enabled: true, Matchers: []Matcher{{Type: "prefix", Value: "x"}}}},
		{{Key: "ok", Name: "x", Enabled: true, Matchers: []Matcher{{Type: "regex", Value: "["}}}},
		{{Key: "ok", Name: "x", Enabled: true, Matchers: []Matcher{{Type: "prefix", Value: "x"}}}, {Key: "ok", Name: "y", Enabled: true, Matchers: []Matcher{{Type: "prefix", Value: "y"}}}},
	} {
		if _, err := NewProfileMatcher(profiles); err == nil {
			t.Errorf("NewProfileMatcher(%#v) error = nil", profiles)
		}
	}
}
