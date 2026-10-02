package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/AgentFeature/agentsearch/internal/models"
	"gopkg.in/yaml.v3"
)

// MergeAndConvert merges Sherlock/Maigret JSON databases into one YAML file.
func MergeAndConvert(output string, inputs ...string) error {
	merged := make(map[string]models.SiteConfig)

	for _, path := range inputs {
		data, err := readFileLimit(path, MaxConfigBytes)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		// Detect Maigret by its sites wrapper.
		var wrapper struct {
			Sites json.RawMessage `json:"sites"`
		}
		if err := json.Unmarshal(data, &wrapper); err == nil && len(wrapper.Sites) > 0 {
			// Maigret database.
			sites, err := parseMaigret(wrapper.Sites)
			if err != nil {
				return fmt.Errorf("parse maigret %s: %w", path, err)
			}
			mergeInto(merged, sites)
			continue
		}

		// Sherlock uses a flat object.
		sites, err := parseSherlock(data)
		if err != nil {
			return fmt.Errorf("parse sherlock %s: %w", path, err)
		}
		mergeInto(merged, sites)
	}

	// Sort the merged records and exclude entries without a URL.
	var list []models.SiteConfig
	for _, s := range merged {
		if strings.TrimSpace(s.URL) == "" {
			continue // Skip engine-only entries without a direct URL.
		}
		list = append(list, s)
	}
	sort.Slice(list, func(i, j int) bool {
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})

	out, err := yaml.Marshal(list)
	if err != nil {
		return fmt.Errorf("marshal yaml: %w", err)
	}

	if err := os.WriteFile(output, out, 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// parseSherlock decodes a flat Sherlock JSON database.
func parseSherlock(data []byte) (map[string]models.SiteConfig, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	result := make(map[string]models.SiteConfig)
	for name, body := range raw {
		if name == "$schema" {
			continue
		}
		var s sherlockSite
		if err := json.Unmarshal(body, &s); err != nil {
			continue // Skip malformed entries.
		}
		result[name] = s.toSiteConfig(name)
	}
	return result, nil
}

// parseMaigret decodes the sites object in a Maigret database.
func parseMaigret(sitesRaw json.RawMessage) (map[string]models.SiteConfig, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(sitesRaw, &raw); err != nil {
		return nil, err
	}

	result := make(map[string]models.SiteConfig)
	for name, body := range raw {
		var s maigretSite
		if err := json.Unmarshal(body, &s); err != nil {
			continue
		}
		result[name] = s.toSiteConfig(name)
	}
	return result, nil
}

func mergeInto(dst, src map[string]models.SiteConfig) {
	for k, v := range src {
		key := k
		if existing, ok := dst[key]; ok {
			if existing.URL == v.URL {
				continue // Exact duplicate.
			}
			// Distinguish sites with the same name but different URLs.
			suffix := sanitizeKey(v.URL)
			key = fmt.Sprintf("%s_%s", k, suffix)
			v.Name = fmt.Sprintf("%s (%s)", v.Name, suffix)
		}
		dst[key] = v
	}
}

func sanitizeKey(url string) string {
	replacer := strings.NewReplacer(
		"https://", "", "http://", "", "/", "_", ".", "_",
		"{", "", "}", "", "-", "_",
	)
	return strings.Trim(replacer.Replace(url), "_")
}

// --- Sherlock intermediate structure ---

type sherlockSite struct {
	ErrorType         string            `json:"errorType"`
	ErrorMsg          json.RawMessage   `json:"errorMsg"` // string or []string
	ErrorURL          string            `json:"errorUrl"`
	RegexCheck        string            `json:"regexCheck"`
	URL               string            `json:"url"`
	URLMain           string            `json:"urlMain"`
	URLProbe          string            `json:"urlProbe"`
	UsernameClaimed   string            `json:"username_claimed"`
	UsernameUnclaimed string            `json:"username_unclaimed"`
	Headers           map[string]string `json:"headers"`
	RequestHeadOnly   bool              `json:"request_head_only"`
	IsNSFW            bool              `json:"isNSFW"`
}

func (s *sherlockSite) toSiteConfig(name string) models.SiteConfig {
	cfg := models.SiteConfig{
		Name:              name,
		URL:               normalizeURL(s.URL),
		URLProbe:          normalizeURL(s.URLProbe),
		URLMain:           s.URLMain,
		CheckType:         s.ErrorType,
		ErrorURL:          s.ErrorURL,
		RegexCheck:        s.RegexCheck,
		Headers:           s.Headers,
		RequestHeadOnly:   s.RequestHeadOnly,
		UsernameClaimed:   s.UsernameClaimed,
		UsernameUnclaimed: s.UsernameUnclaimed,
		Weight:            10,
	}
	if s.IsNSFW {
		cfg.Tags = append(cfg.Tags, "nsfw")
	}

	// errorMsg can be a string or an array.
	var msgs []string
	if len(s.ErrorMsg) > 0 {
		if s.ErrorMsg[0] == '[' {
			_ = json.Unmarshal(s.ErrorMsg, &msgs)
		} else {
			var single string
			_ = json.Unmarshal(s.ErrorMsg, &single)
			if single != "" {
				msgs = append(msgs, single)
			}
		}
	}
	cfg.AbsenceStrs = msgs

	// Default status-code absence checks to HTTP 404.
	if cfg.CheckType == "status_code" && cfg.ErrorCode == 0 {
		cfg.ErrorCode = 404
	}

	return cfg
}

// --- Maigret intermediate structure ---

type maigretSite struct {
	URL               string            `json:"url"`
	URLMain           string            `json:"urlMain"`
	URLProbe          string            `json:"urlProbe"`
	CheckType         string            `json:"checkType"`
	AbsenceStrs       []string          `json:"absenceStrs"`
	PresenceStrs      []string          `json:"presenceStrs"` // Canonical spelling.
	PresenseStrs      []string          `json:"presenseStrs"` // Legacy upstream misspelling.
	Headers           map[string]string `json:"headers"`
	Disabled          bool              `json:"disabled"`
	UsernameClaimed   string            `json:"usernameClaimed"`
	UsernameUnclaimed string            `json:"usernameUnclaimed"`
	RegexCheck        string            `json:"regexCheck"`
	Tags              []string          `json:"tags"`
	AlexaRank         int               `json:"alexaRank"`
	Engine            string            `json:"engine"`
	RequestMethod     string            `json:"requestMethod"`
	RequestPayload    json.RawMessage   `json:"requestPayload"` // Object or string.
	Errors            map[string]string `json:"errors"`
	Protection        []string          `json:"protection"`
	Source            string            `json:"source"`
}

func (m *maigretSite) toSiteConfig(name string) models.SiteConfig {
	cfg := models.SiteConfig{
		Name:              name,
		URL:               normalizeURL(m.URL),
		URLProbe:          normalizeURL(m.URLProbe),
		URLMain:           m.URLMain,
		CheckType:         m.CheckType,
		AbsenceStrs:       m.AbsenceStrs,
		PresenceStrs:      mergeSlices(m.PresenceStrs, m.PresenseStrs),
		Headers:           m.Headers,
		Disabled:          m.Disabled,
		RegexCheck:        m.RegexCheck,
		Tags:              m.Tags,
		AlexaRank:         m.AlexaRank,
		Engine:            m.Engine,
		RequestMethod:     m.RequestMethod,
		Protection:        m.Protection,
		Source:            m.Source,
		UsernameClaimed:   m.UsernameClaimed,
		UsernameUnclaimed: m.UsernameUnclaimed,
		Weight:            10,
	}

	// Retain structured payloads as JSON; unwrap string payloads.
	if len(m.RequestPayload) > 0 {
		if m.RequestPayload[0] == '{' || m.RequestPayload[0] == '[' {
			cfg.RequestPayload = string(m.RequestPayload)
		} else {
			var s string
			_ = json.Unmarshal(m.RequestPayload, &s)
			cfg.RequestPayload = s
		}
	}

	// Infer a check type when none is specified.
	if cfg.CheckType == "" {
		switch {
		case cfg.ErrorCode != 0:
			cfg.CheckType = "status_code"
		case len(cfg.AbsenceStrs) > 0:
			cfg.CheckType = "message"
		case cfg.ErrorURL != "":
			cfg.CheckType = "response_url"
		}
	}

	return cfg
}

func normalizeURL(u string) string {
	if u == "" {
		return ""
	}
	// Sherlock uses {} for the username placeholder.
	u = strings.ReplaceAll(u, "{}", "{username}")
	// Engine-specific Maigret placeholders are not resolved; remove them.
	u = strings.ReplaceAll(u, "{urlMain}", "")
	u = strings.ReplaceAll(u, "{urlSubpath}", "")
	return u
}

func mergeSlices(a, b []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range a {
		if _, ok := seen[s]; !ok && s != "" {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok && s != "" {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
