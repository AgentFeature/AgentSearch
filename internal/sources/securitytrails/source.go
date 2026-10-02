package securitytrails

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
		return nil, errors.New("SecurityTrails source requires a client")
	}
	return &Source{client: client}, nil
}
func (*Source) Name() string            { return "securitytrails" }
func (*Source) Type() models.SourceType { return models.SourceAPI }

// SearchDomain emits one attributed observation. Found means a matching provider
// domain profile, not live DNS verification or maliciousness. No documented
// definitive absence contract exists for this endpoint, so 404 remains an error.
func (s *Source) SearchDomain(ctx context.Context, domain string, emit sources.Emit) error {
	if emit == nil {
		return errors.New("SecurityTrails source requires a result consumer")
	}
	start := time.Now()
	target, validationErr := models.NewDomainTarget(domain)
	result := models.NewResult(s.Name(), s.Type(), target)
	result.TargetType = models.TargetDomain
	result.SiteName = "SecurityTrails"
	result.URL = "https://securitytrails.com/"
	var data *domainData
	var err error
	if validationErr != nil {
		err = &Error{Kind: "bad_request"}
	} else {
		data, err = s.client.lookup(ctx, target.Value())
	}
	result.Duration = time.Since(start)
	if err != nil {
		result.Status = models.StatusError
		result.Error = err.Error()
		result.Metadata = errorMetadata(err)
	} else {
		result.Status = models.StatusFound
		result.Confidence = 100
		result.Metadata = map[string]string{"method": "domain-current-dns", "scope": "provider_observation", "dns_record_count": strconv.Itoa(len(data.records))}
		result.Evidence = []models.Evidence{{Kind: "domain", Value: target.Value()}}
		for _, r := range data.records {
			result.Evidence = append(result.Evidence, models.Evidence{Kind: r.kind, Value: r.value})
		}
	}
	key := s.client.key.Reveal()
	if consumerErr := emit(result.Redacted(key, strings.ToLower(key)).Normalized()); consumerErr != nil {
		return consumerErr
	}
	return err
}

var _ sources.DomainSearcher = (*Source)(nil)
var _ sources.Source = (*Source)(nil)
