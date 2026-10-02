# External intelligence — SecurityTrails domain provider

## Selection decision (2026-09-10)

One new provider is implemented: **SecurityTrails Get Domain**, for a passive view of a domain's
current DNS records as observed by that provider. This is enough to extend the existing
capability/registry mechanism without creating a provider framework or correlation engine.

Candidates were considered in the requested priority order:

| Priority | Decision |
| --- | --- |
| Email | Existing HIBP already supplies breach evidence; do not duplicate it. Hunter documents email verification/enrichment APIs [1](https://help.hunter.io/en/articles/1970956-hunter-api), but those are a different objective from exposure evidence. Deferred in favor of DNS intelligence, not rejected as an invalid API. |
| Domain | SecurityTrails selected: documented read-only endpoint, header authentication, structured DNS observations and explicit API licensing conditions. |
| Username, IP, URL | Not evaluated further after selecting a useful initial provider. No claims about VirusTotal, AbuseIPDB or URLScan suitability are made. A second domain provider is not required. |

Only official API documentation was used to implement the contract. No scraping, scanning,
browser automation, private endpoints or third-party API wrappers are used.

## Official contract and operational restrictions

- [Get Domain](https://docs.securitytrails.com/reference/get-domain-old-1):
  `GET https://api.securitytrails.com/v1/domain/{hostname}`. Despite the documentation page's
  historical slug, its embedded OpenAPI definition marks this operation `deprecated: false`.
- [Authentication](https://docs.securitytrails.com/docs/authentication): use the `APIKEY` header.
  The documentation discourages query-string authentication; AgentSearch never uses it.
- [Quotas and rate limits](https://docs.securitytrails.com/docs/quotas-rate-limits): both monthly
  exhaustion and per-second throttling can return 429; account limits vary. AgentSearch defaults
  to 1s request-start spacing per client and has no automatic retries or billing changes.
- HTTP status handling follows the official errors documentation [1](https://docs.securitytrails.com/docs/errors).
  Invalid input (400), authentication (401), access (403), quota/rate (429) and service failures
  are errors, not absence. The Get Domain contract does not document a definitive negative
  lookup: **404 is an error**, not proof that a domain is unregistered or unknown.
- [Recorded Future Terms of Use](https://www.recordedfuture.com/legal/terms-of-use), reached from
  SecurityTrails' terms link, includes SecurityTrails in its definitions. Sections 1 and 3 limit
  use to internal security purposes and the applicable agreement; free-service use is restricted
  to internal non-commercial security purposes. Section 3(C) makes programmatic access subject
  to an API license, API type and subscribed quota. Sections 3(A/B) restrict public disclosure,
  redistribution, resale and third-party/service-bureau use unless separately permitted.

**An API key is not a redistribution license.** Obtain the subscription/API entitlement required
for your use. Keep the AgentSearch HTTP endpoint restricted to authorized internal users under
that agreement; do not expose SecurityTrails data as a public/re-sold intelligence service.
Protect generated CLI output as provider-licensed data. Your order form may add or change rights
and obligations. Review current terms before deployment; this is not legal advice or permission.

## Deliberately narrow data model

Input is one bare ASCII/punycode DNS hostname. No URL, IP, wildcard or search DSL is accepted.
There is no DNS resolution or request to the target itself: only the configured API is contacted.

The client requires a matching `hostname` and a non-null `current_dns` object. For non-null
selected record families, `values` must be an array and each selected value must have its required
correctly typed fields. IP versions, hostname syntax and MX priorities are validated. Missing/null
families mean no observation for that family, not verified absence of the domain. Harmless unknown
fields are ignored. Malformed or insufficient required fields fail closed.

The source emits one existing `models.Result` with attributable, sorted evidence:

- `domain`: the matching canonical hostname;
- `dns_a` / `dns_aaaa`: canonical IP addresses;
- `dns_mx`: priority followed by mail-exchanger hostname (including a valid null MX `0 .`);
- `dns_ns`: canonical nameserver hostname.

No WHOIS contacts, TXT verification tokens, SOA email, raw response bodies, provider scores,
network-neighbor pivots or historical/bulk endpoints are retained. Responses are bounded to 2 MiB
and 2,048 selected DNS records. No silent truncation occurs: exceeding either cap is an error.

`found` with confidence 100 denotes an exact matching provider profile. Even an empty selected DNS
set can accompany that profile; metadata records `dns_record_count: "0"`. This is **not** a claim
that the domain exists in authoritative DNS, has been compromised, is malicious, or is safe.
There is no probabilistic score or supported `not_found` mapping in this initial integration.

## Extension boundary

`models.TargetDomain` and `sources.DomainSearcher` extend the existing contracts. Central domain
composition registers the provider; Runner/Manager still dispatch compatible sources in registry
order, preserve attribution and partial observations, and stop on consumer failure. Future domain
providers can join that registry without provider-specific CLI/HTTP routes. No selector language,
public provider-specific result model or cross-provider deduplication layer was introduced.

The client uses `network.NewServiceClient` with normal TLS verification, bounded reads, a finite
timeout and request contexts. It clones client policy to disable cookies and all redirects. It
uses neither website proxy rotation nor website retries/uTLS. Shared pacing is cancellable and
only briefly locks scheduling state, not network execution. A 429 postpones subsequent request
starts by at least 1s or a longer parsed Retry-After. It never retries the failed lookup. Monthly
quota exhaustion needs operator action; a delay does not restore credits. Multiple processes or
other tools sharing the account must coordinate quotas externally. No cache or quota ledger exists.

## Verification scope

Eight focused provider tests cover success/normalization, empty-profile semantics, HTTP errors
(including non-followed redirects), malformed/required fields, cancellation/deadlines, bounded
responses, pacing/cooldown and credential ownership. Integration tests cover CLI output/exit
status, source isolation, disabled/unused credentials and generic HTTP dispatch/error mapping.
All use local HTTP fixtures and runtime-generated mock credentials.

Live provider verification: **NOT RUN** (no live subscription credential used). Current documented
API availability is not proof of account entitlement or live response compatibility. Native
Windows execution, production throughput and legal suitability remain **UNVERIFIED**.
