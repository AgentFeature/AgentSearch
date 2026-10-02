package models

// SiteConfig defines a website request and its detection rules.
// Converters map Sherlock/Maigret fields into this native schema.
// It also supports regular expressions, redirects, headers and WAF indicators.
type SiteConfig struct {
	Name     string `yaml:"name" json:"name"`
	URL      string `yaml:"url" json:"url"`
	URLProbe string `yaml:"url_probe,omitempty" json:"url_probe,omitempty"`
	URLMain  string `yaml:"url_main,omitempty" json:"url_main,omitempty"`
	Engine   string `yaml:"engine,omitempty" json:"engine,omitempty"`

	RequestMethod   string            `yaml:"request_method,omitempty" json:"request_method,omitempty"`
	RequestPayload  string            `yaml:"request_payload,omitempty" json:"request_payload,omitempty"`
	RequestHeadOnly bool              `yaml:"request_head_only,omitempty" json:"request_head_only,omitempty"`
	Headers         map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// CheckType selects a detection strategy:
	// status_code | message | response_url | header
	CheckType string `yaml:"check_type,omitempty" json:"check_type,omitempty"`

	// Profile absence indicators.
	AbsenceStrs    []string `yaml:"absence_strs,omitempty" json:"absence_strs,omitempty"`
	AbsenceRegexes []string `yaml:"absence_regexes,omitempty" json:"absence_regexes,omitempty"`
	ErrorCode      int      `yaml:"error_code,omitempty" json:"error_code,omitempty"`
	ErrorURL       string   `yaml:"error_url,omitempty" json:"error_url,omitempty"`

	// Profile presence indicators.
	PresenceStrs    []string `yaml:"presence_strs,omitempty" json:"presence_strs,omitempty"`
	PresenceRegexes []string `yaml:"presence_regexes,omitempty" json:"presence_regexes,omitempty"`

	// Redirect rules.
	FollowRedirects         bool     `yaml:"follow_redirects,omitempty" json:"follow_redirects,omitempty"`
	RedirectFailurePatterns []string `yaml:"redirect_failure_patterns,omitempty" json:"redirect_failure_patterns,omitempty"`

	// Response header checks.
	RequiredHeaders map[string]string `yaml:"required_headers,omitempty" json:"required_headers,omitempty"`

	// WAF and protection indicators.
	WAFIndicators WAFConfig `yaml:"waf_indicators,omitempty" json:"waf_indicators,omitempty"`
	Protection    []string  `yaml:"protection,omitempty" json:"protection,omitempty"`
	Disabled      bool      `yaml:"disabled,omitempty" json:"disabled,omitempty"`

	Weight int      `yaml:"weight,omitempty" json:"weight,omitempty"`
	Tags   []string `yaml:"tags,omitempty" json:"tags,omitempty"`

	// Username validation pattern (stored, not currently enforced).
	RegexCheck string `yaml:"regex_check,omitempty" json:"regex_check,omitempty"`

	// Metadata retained during conversion but not used by detection.
	UsernameClaimed   string `yaml:"username_claimed,omitempty" json:"username_claimed,omitempty"`
	UsernameUnclaimed string `yaml:"username_unclaimed,omitempty" json:"username_unclaimed,omitempty"`
	AlexaRank         int    `yaml:"alexa_rank,omitempty" json:"alexa_rank,omitempty"`
	Source            string `yaml:"source,omitempty" json:"source,omitempty"`
}

// WAFConfig contains site-specific protection indicators.
type WAFConfig struct {
	StatusCodes    []int    `yaml:"status_codes,omitempty" json:"status_codes,omitempty"`
	HeaderKeys     []string `yaml:"header_keys,omitempty" json:"header_keys,omitempty"`
	BodySubstrings []string `yaml:"body_substrings,omitempty" json:"body_substrings,omitempty"`
}
