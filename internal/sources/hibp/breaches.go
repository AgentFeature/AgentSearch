package hibp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

const maxBreachResponse = 2 * 1024 * 1024

// Breaches returns full, allowlisted breach metadata in one authenticated call.
// HTTP 404 and an empty JSON array both mean no returned breaches, not failure.
func (c *Client) Breaches(ctx context.Context, email string) ([]Breach, error) {
	target, err := models.NewEmailTarget(email)
	if err != nil {
		return nil, &Error{Kind: BadRequest}
	}
	resp, err := c.get(ctx, "/breachedaccount/"+url.PathEscape(target.Value())+"?truncateResponse=false")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return []Breach{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	data, err := readResponse(ctx, resp, maxBreachResponse)
	if err != nil {
		return nil, err
	}

	var breaches []Breach
	if err := json.Unmarshal(data, &breaches); err != nil || breaches == nil {
		return nil, &Error{Kind: InvalidResponse, StatusCode: resp.StatusCode}
	}
	for _, breach := range breaches {
		if strings.TrimSpace(breach.Name) == "" {
			return nil, &Error{Kind: InvalidResponse, StatusCode: resp.StatusCode}
		}
	}
	return breaches, nil
}

type Source struct{ client *Client }

func NewSource(client *Client) (*Source, error) {
	if client == nil {
		return nil, fmt.Errorf("HIBP source requires a client")
	}
	return &Source{client: client}, nil
}
func (*Source) Name() string            { return "hibp" }
func (*Source) Type() models.SourceType { return models.SourceAPI }

// SearchEmail emits one result per returned breach, or one not_found/error
// result. Confidence 100 denotes an exact API match, not breach verification or
// the probability of a currently compromised account.
func (s *Source) SearchEmail(ctx context.Context, email string, emit sources.Emit) error {
	if emit == nil {
		return fmt.Errorf("HIBP source requires a result consumer")
	}
	start := time.Now()
	target, validationErr := models.NewEmailTarget(email)
	result := models.NewResult(s.Name(), s.Type(), target)
	result.URL = "https://haveibeenpwned.com/"
	result.SiteName = "Have I Been Pwned"
	var breaches []Breach
	var err error
	if validationErr != nil {
		result.TargetType = models.TargetEmail
		err = &Error{Kind: BadRequest}
	} else {
		breaches, err = s.client.Breaches(ctx, target.Value())
	}
	result.Duration = time.Since(start)
	// Drop known keys even if a remote endpoint echoes one in an allowed field.
	deliver := func(r models.Result) error { return emit(r.Redacted(s.client.key.Reveal()).Normalized()) }
	if err != nil {
		result.Status = models.StatusError
		result.Error = err.Error()
		result.Metadata = errorMetadata(err)
		if consumerErr := deliver(result); consumerErr != nil {
			return consumerErr
		}
		return err
	}
	if len(breaches) == 0 {
		result.Status = models.StatusNotFound
		result.Metadata = map[string]string{"breach_count": "0"}
		return deliver(result)
	}
	for _, breach := range breaches {
		if err := ctx.Err(); err != nil {
			return requestError(ctx, err)
		}
		row := result
		row.Status = models.StatusFound
		row.Confidence = 100
		row.SiteName = "Have I Been Pwned / " + breach.Name
		row.Metadata = map[string]string{
			"breach_name": breach.Name, "breach_title": breach.Title, "domain": breach.Domain,
			"breach_date": breach.BreachDate, "added_date": breach.AddedDate, "modified_date": breach.ModifiedDate,
			"verified": strconv.FormatBool(breach.IsVerified), "fabricated": strconv.FormatBool(breach.IsFabricated),
			"breach_count": strconv.Itoa(len(breaches)),
		}
		for _, class := range breach.DataClasses {
			row.Evidence = append(row.Evidence, models.Evidence{Kind: "compromised_data_class", Value: class})
		}
		if err := deliver(row); err != nil {
			return err
		}
	}
	return nil
}

var _ sources.Source = (*Source)(nil)
var _ sources.EmailSearcher = (*Source)(nil)
