package websites

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/AgentFeature/agentsearch/internal/detector"
	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/worker"
)

// substituteRules replaces {username}/{target} placeholders in detection
// rule strings. Regex rules receive a quoted target so usernames never act
// as pattern metacharacters. The input slice is copied before any change.
func substituteRules(rules []string, target string, quote bool) []string {
	replacement := target
	if quote {
		replacement = regexp.QuoteMeta(target)
	}
	out := rules
	copied := false
	for i, rule := range rules {
		if !strings.Contains(rule, "{username}") && !strings.Contains(rule, "{target}") {
			continue
		}
		if !copied {
			out = append([]string(nil), rules...)
			copied = true
		}
		substituted := strings.ReplaceAll(rule, "{username}", replacement)
		out[i] = strings.ReplaceAll(substituted, "{target}", replacement)
	}
	return out
}

// challengeSniffBytes bounds the prefix read for providers whose contract
// does not require body content. It exists solely so built-in WAF and
// challenge-page markers (title/head area) remain detectable without
// downloading the full 128 KiB bound for status-classified providers.
const challengeSniffBytes = 16 * 1024

// fetchOutcome is the shared result of one acquired provider response.
type fetchOutcome struct {
	pr           detector.Response
	transportErr string
	badEncoding  bool
	oversize     bool
}

type fetchEntry struct {
	once sync.Once
	out  fetchOutcome
}

// fetchCache deduplicates identical requests within one search run: the
// first worker performs the fetch, any provider sharing the exact request
// reuses the bounded response for its own classification.
type fetchCache struct {
	mu      sync.Mutex
	entries map[string]*fetchEntry
}

func newFetchCache() *fetchCache {
	return &fetchCache{entries: make(map[string]*fetchEntry)}
}

func (c *fetchCache) do(key string, fetch func() fetchOutcome) fetchOutcome {
	c.mu.Lock()
	entry := c.entries[key]
	if entry == nil {
		entry = &fetchEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()
	entry.once.Do(func() { entry.out = fetch() })
	return entry.out
}

// siteProcessor implements worker.Processor for website checks.
type siteProcessor struct {
	source *Source
	target string
	kind   models.TargetType
	cache  *fetchCache
}

// Process classifies one provider for the target: request planning state
// is immutable, acquisition is deduplicated and bounded, and detection
// runs on the transport-neutral response representation.
func (p *siteProcessor) Process(ctx context.Context, job worker.Job) (res models.Result) {
	start := time.Now()
	plan := p.source.planFor(job.Site.Name)

	res = models.Result{
		Source:     job.Site.Name,
		SourceType: models.SourceWebsite,
		TargetType: p.kind,
		SiteName:   job.Site.Name,
		Target:     p.target,
		Status:     models.StatusError,
	}
	if plan == nil {
		res.Error = "unknown site plan"
		res.Duration = time.Since(start)
		return res.Normalized()
	}

	// Substitute the target into the URL and payload templates.
	checkURL := strings.ReplaceAll(plan.template, "{username}", p.target)
	checkURL = strings.ReplaceAll(checkURL, "{target}", p.target)
	payload := ""
	if plan.site.RequestPayload != "" {
		payload = strings.ReplaceAll(plan.site.RequestPayload, "{username}", p.target)
		payload = strings.ReplaceAll(payload, "{target}", p.target)
	}
	res.URL = checkURL

	// Include elapsed time and redact configured credentials on every return path.
	secrets := make([]string, 0)
	for key, value := range plan.site.Headers {
		if security.SensitiveKey(key) {
			secrets = append(secrets, value)
		}
	}
	defer func() {
		res.Duration = time.Since(start)
		res = res.Redacted(secrets...).Normalized()
		slog.Debug("website check",
			"site", plan.site.Name,
			"target_type", string(p.kind),
			"status", string(res.Status),
			"http_url", checkURL,
			"latency_ms", res.Duration.Milliseconds())
	}()

	if plan.invalid != "" {
		res.Error = "invalid site configuration: " + plan.invalid
		return res
	}

	out := p.cache.do(plan.requestKey(checkURL, payload), func() fetchOutcome {
		return p.source.acquire(ctx, plan, checkURL, payload, p.target)
	})
	if out.transportErr != "" {
		res.Error = out.transportErr
		return res
	}
	pr := out.pr

	// Provider failures, undecoded bodies and truncation are not evidence of absence.
	if pr.StatusCode >= 500 {
		res.Error = "website returned a server error"
		return res
	}
	if plan.needsBody && out.badEncoding {
		res.Error = "unsupported website response encoding"
		return res
	}
	if plan.needsBody && out.oversize {
		res.Error = "website response exceeds body limit"
		res.Metadata = map[string]string{"truncated": "true"}
		return res
	}

	// Detection rule strings may reference the target; substitute them per
	// request so configured positive markers can match the requested
	// profile. Copies never mutate the shared plan configuration.
	site := plan.site
	site.AbsenceStrs = substituteRules(site.AbsenceStrs, p.target, false)
	site.PresenceStrs = substituteRules(site.PresenceStrs, p.target, false)
	site.AbsenceRegexes = substituteRules(site.AbsenceRegexes, p.target, true)
	site.PresenceRegexes = substituteRules(site.PresenceRegexes, p.target, true)

	// Interpret the response.
	detection := p.source.detector.Analyze(site, pr)
	res.Found = detection.Found
	res.Confidence = detection.Confidence
	res.Status = detection.Status
	if detection.Status == models.StatusError && res.Error == "" {
		if pr.StatusCode >= 300 && pr.StatusCode < 400 {
			res.Error = "website redirected without a matching redirect rule"
		} else {
			res.Error = "website response matched no configured detection rule"
		}
	}
	if pr.FinalURL != checkURL {
		res.FinalURL = pr.FinalURL
	}

	return res
}

// acquire performs the single bounded HTTP exchange for a request plan and
// converts it into the transport-neutral detection representation. It
// answers "what did the server return", never "does the username exist".
func (s *Source) acquire(ctx context.Context, plan *sitePlan, checkURL, payload, target string) fetchOutcome {
	// Rate limiting per host applies to real network fetches only.
	if err := s.limiter.WaitContext(ctx, checkURL); err != nil {
		return fetchOutcome{transportErr: err.Error()}
	}

	var bodyReader io.Reader
	if payload != "" {
		bodyReader = strings.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, plan.method, checkURL, bodyReader)
	if err != nil {
		return fetchOutcome{transportErr: err.Error()}
	}

	// Apply default and site-specific headers.
	req.Header.Set("User-Agent", s.ua.GetRandom())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	// Let net/http negotiate and decode gzip before the bounded detector read.
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	for k, v := range plan.site.Headers {
		req.Header.Set(k, strings.ReplaceAll(v, "{username}", target))
	}

	// Enforce policy on the outer client, including configured sensitive headers.
	site := plan.site
	clientCopy := *s.client
	previousPolicy := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if !site.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return errors.New("website redirect limit reached")
		}
		previous := via[len(via)-1].URL
		if previous.Scheme == "https" && next.URL.Scheme != "https" {
			return http.ErrUseLastResponse
		}
		if !strings.EqualFold(previous.Host, next.URL.Host) || previous.Scheme != next.URL.Scheme {
			for key := range next.Header {
				if security.SensitiveKey(key) {
					next.Header.Del(key)
				}
			}
		}
		if previousPolicy != nil {
			return previousPolicy(next, via)
		}
		return nil
	}
	client := &clientCopy

	resp, err := client.Do(req)
	if err != nil {
		return fetchOutcome{transportErr: err.Error()}
	}
	defer resp.Body.Close()

	pr := detector.Response{
		StatusCode: resp.StatusCode,
		Header:     make(http.Header, len(plan.headerKeys)),
		FinalURL:   checkURL,
	}
	// Retain only the detection-relevant headers; cookies, credentials and
	// everything else never leave the transport layer.
	for _, key := range plan.headerKeys {
		if value := resp.Header.Get(key); value != "" {
			pr.Header.Set(key, value)
		}
	}

	// Determine the final response URL.
	if resp.Request != nil && resp.Request.URL != nil {
		pr.FinalURL = resp.Request.URL.String()
	}
	// An unfollowed redirect reports the destination the site selected, so
	// redirect-based absence rules keep working without fetching it.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if location, locErr := resp.Location(); locErr == nil {
			pr.FinalURL = location.String()
		}
	}
	pr.Redirected = pr.FinalURL != checkURL

	// Server failures never need the body; nothing downstream may read it.
	if resp.StatusCode >= 500 {
		return fetchOutcome{pr: pr}
	}

	if !plan.fetchBody {
		// The providers sharing this request classify from status, headers
		// and redirect metadata: read only a bounded sniff window so
		// built-in challenge-page markers stay detectable, then stop.
		// Real challenge pages carry their markers in the document head,
		// well inside this window; the sniff is never complete body
		// evidence and never reaches message rules.
		if encoding := resp.Header.Get("Content-Encoding"); encoding == "" || strings.EqualFold(encoding, "identity") {
			sniff, _ := io.ReadAll(io.LimitReader(resp.Body, challengeSniffBytes))
			pr.Body = string(sniff)
		}
		return fetchOutcome{pr: pr}
	}

	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return fetchOutcome{pr: pr, badEncoding: true}
	}
	// Limit the decoded response body to 128 KiB, detecting overflow.
	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 128*1024+1))
	if readErr != nil {
		return fetchOutcome{transportErr: readErr.Error()}
	}
	if len(bodyBytes) > 128*1024 {
		return fetchOutcome{pr: pr, oversize: true}
	}
	pr.Body = string(bodyBytes)
	pr.BodyComplete = true
	return fetchOutcome{pr: pr}
}
