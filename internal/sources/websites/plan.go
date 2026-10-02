package websites

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/AgentFeature/agentsearch/internal/models"
)

// sitePlan is the immutable, validated execution plan for one configured
// provider. It is built once when the source is constructed; per-request
// state (URL and rule substitution) never mutates the plan.
type sitePlan struct {
	site     models.SiteConfig
	index    int    // deterministic result position (sorted by name)
	method   string // resolved HTTP method
	template string // resolved URL template (probe preferred)
	// fetchBody reports whether the HTTP body must be downloaded for this
	// request. needsBody reports whether THIS site's contract requires it;
	// fetchBody is the union across providers sharing an identical request.
	needsBody bool
	fetchBody bool
	// group is the request-affecting signature used for deduplication.
	group string
	// headerKeys lists the response headers detection may consult.
	headerKeys []string
	// invalid carries a validation failure; such plans produce a
	// deterministic error result without any network request.
	invalid string
}

// requestKey identifies an exact request for deduplication. Two providers
// may share one fetch only when every request-affecting input is equal:
// method, URL, payload, redirect policy and provider-configured request
// headers (all captured in the group signature). The User-Agent rotation,
// fixed Accept/language headers, proxy selection and TLS settings are
// uniform source-wide policy, identical for every provider, so they never
// distinguish requests.
func (p *sitePlan) requestKey(checkURL, payload string) string {
	return p.group + "\x00" + checkURL + "\x00" + payload
}

// groupSignature captures every request-affecting plan attribute. Response
// retention attributes (headerKeys, fetchBody) are deliberately excluded:
// they are unioned across the group so one fetch can serve all members.
func groupSignature(site models.SiteConfig, method, template string) string {
	keys := make([]string, 0, len(site.Headers))
	for k := range site.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(method)
	b.WriteString("\x00")
	b.WriteString(template)
	b.WriteString("\x00")
	b.WriteString(site.RequestPayload)
	b.WriteString("\x00")
	if site.FollowRedirects {
		b.WriteString("follow")
	}
	for _, k := range keys {
		b.WriteString("\x00")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(site.Headers[k])
	}
	return b.String()
}

// validationTarget exercises rule templates during plan compilation.
const validationTarget = "plan_validation_sample"

// buildPlans validates and compiles the configured sites into a
// deterministic provider plan: duplicates removed, sorted by name,
// body requirements and detection headers resolved, rule regexes verified.
func buildPlans(sites []models.SiteConfig) ([]sitePlan, map[string]int) {
	seen := make(map[string]bool, len(sites))
	plans := make([]sitePlan, 0, len(sites))
	for _, site := range sites {
		if site.URL == "" || site.Disabled {
			continue
		}
		if seen[site.Name] {
			continue // duplicate provider IDs: first definition wins
		}
		seen[site.Name] = true
		plans = append(plans, compilePlan(site))
	}
	sort.Slice(plans, func(i, j int) bool { return plans[i].site.Name < plans[j].site.Name })

	// Union response requirements across providers sharing an identical
	// request, so one fetch can serve every member of the group: body
	// download when any member reads bodies, and retained detection
	// headers as the merged set.
	needs := make(map[string]bool, len(plans))
	groupHeaders := make(map[string]map[string]bool, len(plans))
	for i := range plans {
		plans[i].group = groupSignature(plans[i].site, plans[i].method, plans[i].template)
		needs[plans[i].group] = needs[plans[i].group] || plans[i].needsBody
		merged := groupHeaders[plans[i].group]
		if merged == nil {
			merged = make(map[string]bool)
			groupHeaders[plans[i].group] = merged
		}
		for _, k := range plans[i].headerKeys {
			merged[k] = true
		}
	}
	index := make(map[string]int, len(plans))
	for i := range plans {
		plans[i].index = i
		plans[i].fetchBody = needs[plans[i].group]
		merged := make([]string, 0, len(groupHeaders[plans[i].group]))
		for k := range groupHeaders[plans[i].group] {
			merged = append(merged, k)
		}
		sort.Strings(merged)
		plans[i].headerKeys = merged
		index[plans[i].site.Name] = i
	}
	return plans, index
}

func compilePlan(site models.SiteConfig) sitePlan {
	plan := sitePlan{site: site}

	plan.method = http.MethodGet
	if site.RequestMethod != "" {
		plan.method = site.RequestMethod
	}
	if site.RequestHeadOnly && plan.method == http.MethodGet {
		plan.method = http.MethodHead
	}

	plan.template = site.URL
	if site.URLProbe != "" {
		plan.template = site.URLProbe
	}

	// The body is downloaded only when detection can use it: message rules
	// read it, and site-specific WAF body markers need it. Status, header,
	// redirect and response-URL contracts classify without body content.
	plan.needsBody = site.CheckType == "message" || len(site.WAFIndicators.BodySubstrings) > 0

	// Detection-relevant response headers, nothing else is retained.
	keys := []string{"CF-RAY", "Server", "Content-Encoding", "Content-Type"}
	for k := range site.RequiredHeaders {
		keys = append(keys, k)
	}
	keys = append(keys, site.WAFIndicators.HeaderKeys...)
	sort.Strings(keys)
	plan.headerKeys = keys

	// Validate the substituted URL once.
	sample := strings.ReplaceAll(plan.template, "{username}", validationTarget)
	sample = strings.ReplaceAll(sample, "{target}", validationTarget)
	if u, err := url.Parse(sample); err != nil || u.Scheme == "" || u.Host == "" {
		plan.invalid = fmt.Sprintf("invalid url template %q", plan.template)
		return plan
	}

	// Validate rule regex templates once, with a quoted sample target —
	// exactly how they are substituted at request time.
	for _, pattern := range append(append([]string(nil), site.AbsenceRegexes...), site.PresenceRegexes...) {
		substituted := strings.ReplaceAll(pattern, "{username}", regexp.QuoteMeta(validationTarget))
		substituted = strings.ReplaceAll(substituted, "{target}", regexp.QuoteMeta(validationTarget))
		if _, err := regexp.Compile(substituted); err != nil {
			plan.invalid = fmt.Sprintf("invalid detection rule regex %q", pattern)
			return plan
		}
	}
	return plan
}
