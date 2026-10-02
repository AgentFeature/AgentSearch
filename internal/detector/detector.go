package detector

import (
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// Response is the bounded, transport-neutral view of a provider reply used
// for detection. The acquisition layer fills it with only the
// detection-relevant headers; it never carries cookies, credentials, or
// unbounded data. Body is empty when the site's contract does not require
// body content, and BodyComplete reports whether the body was fully read
// within the configured bound.
type Response struct {
	StatusCode   int
	Header       http.Header
	FinalURL     string
	Redirected   bool
	Body         string
	BodyComplete bool
}

// DetectionResult describes the interpretation of a server response.
type DetectionResult struct {
	Found      bool
	Confidence int
	Status     models.ResultStatus
}

// Engine applies declarative site detection rules. It caches compiled
// regular expressions so repeated checks do not recompile patterns.
type Engine struct {
	mu      sync.Mutex
	regexes map[string]*regexp.Regexp
}

// New creates a detection engine.
func New() *Engine {
	return &Engine{regexes: make(map[string]*regexp.Regexp)}
}

// matchRegex compiles each pattern once and caches it. Invalid patterns
// never match. The cache is bounded and reset when it grows too large.
func (e *Engine) matchRegex(pattern, body string) bool {
	e.mu.Lock()
	re, ok := e.regexes[pattern]
	if !ok {
		if len(e.regexes) >= 1024 {
			e.regexes = make(map[string]*regexp.Regexp)
		}
		re, _ = regexp.Compile(pattern)
		e.regexes[pattern] = re
	}
	e.mu.Unlock()
	if re == nil {
		return false
	}
	return re.MatchString(body)
}

// Analyze interprets a provider response using SiteConfig rules.
// Rules are applied in this order:
//  1. WAF and protection indicators
//  2. Redirect rules for the final URL
//  3. Unfollowed-redirect classification
//  4. The configured check type
func (e *Engine) Analyze(site models.SiteConfig, pr Response) DetectionResult {
	// Detect WAF responses first.
	if isWAF(pr, site.WAFIndicators) {
		return DetectionResult{Status: models.StatusBlocked, Confidence: 0}
	}

	// Honor explicit protection markers.
	for _, p := range site.Protection {
		if p == "cf_js_challenge" || p == "custom_bot_protection" {
			// An explicit protection marker forces a blocked result,
			// even if response-based WAF heuristics do not match.
			return DetectionResult{Status: models.StatusBlocked, Confidence: 0}
		}
	}

	// Check the final URL for redirect failure patterns.
	for _, pattern := range site.RedirectFailurePatterns {
		if strings.Contains(pr.FinalURL, pattern) {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
	}

	// A redirect response reaching detection was not followed (site policy,
	// an HTTPS downgrade refusal or the hop limit). Its stub body and status
	// are not the requested document: only explicit rules may classify it,
	// using FinalURL, which carries the redirect destination. Anything else
	// is unusable evidence — neither presence nor absence.
	if pr.StatusCode >= 300 && pr.StatusCode < 400 {
		if site.CheckType == "response_url" && site.ErrorURL != "" && strings.Contains(pr.FinalURL, site.ErrorURL) {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
		if site.ErrorCode != 0 && pr.StatusCode == site.ErrorCode {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
		return DetectionResult{Status: models.StatusError, Confidence: 0}
	}

	// Apply the configured detection strategy.
	switch site.CheckType {
	case "status_code":
		return e.checkStatusCode(site, pr)
	case "message":
		return e.checkMessage(site, pr)
	case "response_url":
		return e.checkResponseURL(site, pr)
	case "header":
		return e.checkHeaders(site, pr)
	default:
		// Status heuristics when no check type is configured: the explicit
		// error code, then 2xx success, then 404 absence. Any other status
		// is not evidence in either direction.
		if site.ErrorCode != 0 && pr.StatusCode == site.ErrorCode {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
		if pr.StatusCode >= 200 && pr.StatusCode < 300 {
			return DetectionResult{Found: true, Status: models.StatusFound, Confidence: calculateBaseConfidence(site, pr.StatusCode, pr.Body)}
		}
		if pr.StatusCode == http.StatusNotFound {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
		return DetectionResult{Status: models.StatusError, Confidence: 0}
	}
}

// checkStatusCode implements the explicit status contract: the configured
// error code (or 404) proves absence, 2xx success proves the configured
// existence signal, and any other status is unusable evidence — never a
// silent negative.
func (e *Engine) checkStatusCode(site models.SiteConfig, pr Response) DetectionResult {
	if site.ErrorCode != 0 && pr.StatusCode == site.ErrorCode {
		return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
	}
	// A positive rule signal from 2xx is not proof of profile ownership or activity.
	if pr.StatusCode >= 200 && pr.StatusCode < 300 {
		return DetectionResult{Found: true, Status: models.StatusFound, Confidence: calculateBaseConfidence(site, pr.StatusCode, "")}
	}
	if pr.StatusCode == http.StatusNotFound {
		return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
	}
	return DetectionResult{Status: models.StatusError, Confidence: 0}
}

func (e *Engine) checkMessage(site models.SiteConfig, pr Response) DetectionResult {
	// Absence indicators take precedence over presence indicators.
	for _, s := range site.AbsenceStrs {
		if strings.Contains(pr.Body, s) {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
	}
	for _, reStr := range site.AbsenceRegexes {
		if e.matchRegex(reStr, pr.Body) {
			return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
		}
	}

	// Check presence indicators next.
	for _, s := range site.PresenceStrs {
		if strings.Contains(pr.Body, s) {
			return DetectionResult{Found: true, Status: models.StatusFound, Confidence: calculateBaseConfidence(site, 0, pr.Body)}
		}
	}
	for _, reStr := range site.PresenceRegexes {
		if e.matchRegex(reStr, pr.Body) {
			return DetectionResult{Found: true, Status: models.StatusFound, Confidence: calculateBaseConfidence(site, 0, pr.Body)}
		}
	}

	// No configured indicator matched. An HTTP error status is never
	// presence evidence, and a site with explicit presence rules that all
	// failed produced an ambiguous document, not a profile.
	if pr.StatusCode >= 400 {
		return DetectionResult{Status: models.StatusError, Confidence: 0}
	}
	if len(site.PresenceStrs) > 0 || len(site.PresenceRegexes) > 0 {
		return DetectionResult{Status: models.StatusError, Confidence: 0}
	}

	// Absence-only sites keep the documented low-confidence fallback:
	// their contract is "success without the absence marker means found".
	conf := calculateBaseConfidence(site, 0, pr.Body)
	if conf < 30 {
		conf = 30
	}
	return DetectionResult{Found: true, Status: models.StatusFound, Confidence: conf}
}

func (e *Engine) checkResponseURL(site models.SiteConfig, pr Response) DetectionResult {
	if site.ErrorURL != "" && strings.Contains(pr.FinalURL, site.ErrorURL) {
		return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
	}
	// The response_url contract is "not sent to the error URL means found";
	// an HTTP error status breaks that assumption and proves nothing.
	if pr.StatusCode >= 400 {
		return DetectionResult{Status: models.StatusError, Confidence: 0}
	}
	return DetectionResult{Found: true, Status: models.StatusFound, Confidence: calculateBaseConfidence(site, 0, "")}
}

func (e *Engine) checkHeaders(site models.SiteConfig, pr Response) DetectionResult {
	for k, v := range site.RequiredHeaders {
		if pr.Header.Get(k) == v {
			return DetectionResult{Found: true, Status: models.StatusFound, Confidence: calculateBaseConfidence(site, pr.StatusCode, "")}
		}
	}
	return DetectionResult{Status: models.StatusNotFound, Confidence: 0}
}

// isWAF identifies protection responses using blocking evidence, not mere
// vendor presence: a CDN header such as CF-RAY on an ordinary 200/404 page
// is how much of the web is served and proves nothing. Blocking requires a
// challenge/deny status or an explicit challenge-page marker, plus the
// operator-configured site-specific rules, which stay authoritative.
func isWAF(pr Response, cfg models.WAFConfig) bool {
	lowerBody := strings.ToLower(pr.Body)
	blockStatus := pr.StatusCode == 403 || pr.StatusCode == 429 || pr.StatusCode == 503

	// Built-in heuristics.
	if pr.StatusCode == 429 {
		return true
	}
	cloudflareFronted := pr.Header.Get("CF-RAY") != "" ||
		strings.Contains(strings.ToLower(pr.Header.Get("Server")), "cloudflare")
	if cloudflareFronted && blockStatus {
		return true
	}
	if blockStatus && (strings.Contains(lowerBody, "cloudflare") || strings.Contains(lowerBody, "ray id")) {
		return true
	}
	// Explicit challenge-page markers are blocking evidence at any status.
	for _, marker := range []string{"cf-chl", "just a moment", "checking your browser", "ddos-guard", "incapsula", "sucuri"} {
		if strings.Contains(lowerBody, marker) {
			return true
		}
	}

	// Site-specific WAF rules.
	for _, code := range cfg.StatusCodes {
		if pr.StatusCode == code {
			return true
		}
	}
	for _, key := range cfg.HeaderKeys {
		if pr.Header.Get(key) != "" {
			return true
		}
	}
	for _, sub := range cfg.BodySubstrings {
		if strings.Contains(lowerBody, strings.ToLower(sub)) {
			return true
		}
	}

	return false
}

// calculateBaseConfidence combines the site weight and response heuristics.
// statusCode contributes only for status-oriented checks; callers pass 0
// to skip the bonus, preserving the historical confidence values.
func calculateBaseConfidence(site models.SiteConfig, statusCode int, body string) int {
	score := site.Weight
	if score == 0 {
		score = 10
	}

	if statusCode == 200 {
		score += 30
	}

	// A substantial body contributes a small confidence bonus.
	if len(body) > 200 {
		score += 10
	}

	if score > 100 {
		score = 100
	}
	return score
}
