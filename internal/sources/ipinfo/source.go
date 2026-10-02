package ipinfo

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

type Source struct{ client *Client }

func NewSource(client *Client) (*Source, error) {
	if client == nil {
		return nil, errors.New("IPinfo source requires a client")
	}
	return &Source{client}, nil
}
func (*Source) Name() string            { return "ipinfo" }
func (*Source) Type() models.SourceType { return models.SourceAPI }

// SearchIP reports provider profile data, not ownership/location certainty,
// activity or security status. No documented negative contract is assumed.
func (s *Source) SearchIP(ctx context.Context, ip string, emit sources.Emit) error {
	if emit == nil {
		return errors.New("IPinfo source requires a result consumer")
	}
	start := time.Now()
	target, err := models.NewIPTarget(ip)
	row := models.NewResult(s.Name(), s.Type(), target)
	row.TargetType = models.TargetIP
	row.SiteName = "IPinfo Lite"
	row.URL = "https://ipinfo.io/"
	var p *profile
	if err != nil {
		err = &Error{Kind: "bad_request"}
	} else {
		p, err = s.client.lookup(ctx, target.Value())
	}
	row.Duration = time.Since(start)
	if err != nil {
		row.Status = models.StatusError
		row.Error = err.Error()
		row.Metadata = map[string]string{}
		var e *Error
		if errors.As(err, &e) {
			row.Metadata["error_kind"] = safeKind(e.Kind)
			if e.StatusCode != 0 {
				row.Metadata["http_status"] = strconv.Itoa(e.StatusCode)
			}
			if e.RetryAfterSeconds > 0 {
				row.Metadata["retry_after_seconds"] = strconv.FormatUint(e.RetryAfterSeconds, 10)
			}
		}
	} else {
		row.Status = models.StatusFound
		row.Confidence = 100
		row.Metadata = map[string]string{"method": "ipinfo-lite", "scope": "provider_observation"}
		row.Evidence = []models.Evidence{{Kind: "ip", Value: p.IP}}
		for _, field := range []models.Evidence{{Kind: "asn", Value: p.ASN}, {Kind: "as_name", Value: p.ASName}, {Kind: "as_domain", Value: p.ASDomain}, {Kind: "country_code", Value: p.CountryCode}, {Kind: "country", Value: p.Country}, {Kind: "continent_code", Value: p.ContinentCode}, {Kind: "continent", Value: p.Continent}} {
			if field.Value != "" {
				row.Metadata[field.Kind] = field.Value
				row.Evidence = append(row.Evidence, field)
			}
		}
		if p.Bogon != nil {
			row.Metadata["bogon"] = strconv.FormatBool(*p.Bogon)
			row.Evidence = append(row.Evidence, models.Evidence{Kind: "bogon", Value: row.Metadata["bogon"]})
		}
	}
	key := s.client.key.Reveal()
	if consumerErr := emit(row.Redacted(key, strings.ToLower(key)).Normalized()); consumerErr != nil {
		return consumerErr
	}
	return err
}

var _ sources.IPSearcher = (*Source)(nil)
