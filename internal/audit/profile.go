package audit

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var profileKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)

type Matcher struct {
	Type          string `json:"type"`
	Value         string `json:"value"`
	CaseSensitive bool   `json:"case_sensitive"`
}

type ClientProfile struct {
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Priority    int       `json:"priority"`
	Enabled     bool      `json:"enabled"`
	Matchers    []Matcher `json:"matchers"`
}

type compiledMatcher struct {
	kind          string
	value         string
	caseSensitive bool
	regex         *regexp.Regexp
}

type compiledProfile struct {
	profile  ClientProfile
	matchers []compiledMatcher
}

type ProfileMatcher struct {
	profiles []compiledProfile
}

func NewProfileMatcher(profiles []ClientProfile) (*ProfileMatcher, error) {
	seen := make(map[string]struct{}, len(profiles))
	compiled := make([]compiledProfile, 0, len(profiles))
	for _, profile := range profiles {
		profile.Key = strings.ToLower(strings.TrimSpace(profile.Key))
		profile.Name = strings.TrimSpace(profile.Name)
		profile.Description = strings.TrimSpace(profile.Description)
		if !profileKeyPattern.MatchString(profile.Key) || profile.Name == "" || len(profile.Name) > 120 || len(profile.Description) > 500 {
			return nil, fmt.Errorf("invalid client profile %q", profile.Key)
		}
		if _, duplicate := seen[profile.Key]; duplicate {
			return nil, fmt.Errorf("duplicate client profile %q", profile.Key)
		}
		seen[profile.Key] = struct{}{}
		if len(profile.Matchers) == 0 || len(profile.Matchers) > 32 {
			return nil, fmt.Errorf("client profile %q must have 1 to 32 matchers", profile.Key)
		}
		runtime := compiledProfile{profile: profile, matchers: make([]compiledMatcher, 0, len(profile.Matchers))}
		for _, matcher := range profile.Matchers {
			item, err := compileMatcher(matcher)
			if err != nil {
				return nil, fmt.Errorf("client profile %q: %w", profile.Key, err)
			}
			runtime.matchers = append(runtime.matchers, item)
		}
		if profile.Enabled {
			compiled = append(compiled, runtime)
		}
	}
	sort.SliceStable(compiled, func(i, j int) bool {
		if compiled[i].profile.Priority != compiled[j].profile.Priority {
			return compiled[i].profile.Priority < compiled[j].profile.Priority
		}
		return compiled[i].profile.Key < compiled[j].profile.Key
	})
	return &ProfileMatcher{profiles: compiled}, nil
}

func compileMatcher(matcher Matcher) (compiledMatcher, error) {
	kind := strings.ToLower(strings.TrimSpace(matcher.Type))
	value := strings.TrimSpace(matcher.Value)
	if value == "" || len(value) > 512 {
		return compiledMatcher{}, errors.New("client matcher is empty or too long")
	}
	result := compiledMatcher{kind: kind, value: value, caseSensitive: matcher.CaseSensitive}
	switch kind {
	case "prefix":
		return result, nil
	case "exact":
		return result, nil
	case "regex":
		pattern := value
		if !matcher.CaseSensitive {
			pattern = "(?i:" + value + ")"
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return compiledMatcher{}, fmt.Errorf("invalid RE2 matcher: %w", err)
		}
		result.regex = compiled
		return result, nil
	default:
		return compiledMatcher{}, errors.New("client matcher type must be exact, prefix, or regex")
	}
}

// Match returns only explicitly recognized clients. Valid but unmatched and
// malformed User-Agent values both bypass v0.1 auditing by product decision.
func (matcher *ProfileMatcher) Match(userAgent string) (ClientProfile, bool) {
	if matcher == nil || !ValidUserAgent(userAgent) {
		return ClientProfile{}, false
	}
	userAgent = strings.TrimSpace(userAgent)
	for _, profile := range matcher.profiles {
		for _, item := range profile.matchers {
			if item.matches(userAgent) {
				return profile.profile, true
			}
		}
	}
	return ClientProfile{}, false
}

func (matcher compiledMatcher) matches(userAgent string) bool {
	switch matcher.kind {
	case "exact":
		if matcher.caseSensitive {
			return userAgent == matcher.value
		}
		return strings.EqualFold(userAgent, matcher.value)
	case "prefix":
		if matcher.caseSensitive {
			return strings.HasPrefix(userAgent, matcher.value)
		}
		if len(userAgent) < len(matcher.value) {
			return false
		}
		return strings.EqualFold(userAgent[:len(matcher.value)], matcher.value)
	case "regex":
		return matcher.regex != nil && matcher.regex.MatchString(userAgent)
	default:
		return false
	}
}

func ValidUserAgent(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > DefaultEventClientMaxSize || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func SanitizeUserAgent(value string) string {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return ""
	}
	var builder strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) {
			continue
		}
		builder.WriteRune(r)
		if builder.Len() >= DefaultEventClientMaxSize {
			break
		}
	}
	result := builder.String()
	for len(result) > DefaultEventClientMaxSize {
		_, size := utf8.DecodeLastRuneInString(result)
		result = result[:len(result)-size]
	}
	return result
}

func DefaultClientProfiles() []ClientProfile {
	return []ClientProfile{
		{Key: "codex_vscode", Name: "Codex VS Code", Priority: 10, Enabled: true, Matchers: []Matcher{
			{Type: "prefix", Value: "codex_vscode/", CaseSensitive: false},
			{Type: "prefix", Value: "codex_vscode_copilot/", CaseSensitive: false},
		}},
		{Key: "codex_cli", Name: "Codex CLI", Priority: 20, Enabled: true, Matchers: []Matcher{
			{Type: "prefix", Value: "codex_cli_rs/", CaseSensitive: false},
			{Type: "prefix", Value: "codex-tui/", CaseSensitive: false},
		}},
		{Key: "codex_desktop", Name: "Codex Desktop", Priority: 30, Enabled: true, Matchers: []Matcher{
			{Type: "prefix", Value: "Codex Desktop/", CaseSensitive: false},
			{Type: "prefix", Value: "codex_chatgpt_desktop/", CaseSensitive: false},
		}},
	}
}
