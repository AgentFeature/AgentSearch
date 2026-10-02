package hibp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" // Required by the range protocol, not used for password storage.
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
	"github.com/AgentFeature/agentsearch/internal/sources"
)

// passwordSHA1 runs only locally. No normalization or trimming of the password
// is permitted. Prefix/suffix are short-lived lookup material, never results.
func passwordSHA1(password []byte) (prefix, suffix string) {
	sum := sha1.Sum(password)
	var encoded [sha1.Size * 2]byte
	hex.Encode(encoded[:], sum[:])
	for i, b := range encoded {
		if b >= 'a' && b <= 'f' {
			encoded[i] = b - 'a' + 'A'
		}
	}
	prefix = string(encoded[:5])
	suffix = string(encoded[5:])
	clear(sum[:])
	clear(encoded[:])
	return prefix, suffix
}
func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, b := range []byte(value) {
		if !((b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}

// matchRange validates the entire response, even after a match. Blank lines
// are ignored; empty responses, malformed records, duplicates and overflow are
// errors. Zero counts are padding and never constitute a pwned match.
func matchRange(data []byte, localSuffix string) (uint64, error) {
	invalid := func() (uint64, error) { return 0, &Error{Kind: InvalidResponse, StatusCode: http.StatusOK} }
	if !validHex(localSuffix, 35) {
		return invalid()
	}
	localSuffix = strings.ToUpper(localSuffix)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 128), 128)
	seen := make(map[string]struct{})
	var occurrences uint64
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		suffix, count, ok := strings.Cut(line, ":")
		if !ok || !validHex(suffix, 35) || count == "" {
			return invalid()
		}
		for _, b := range []byte(count) {
			if b < '0' || b > '9' {
				return invalid()
			}
		}
		n, err := strconv.ParseUint(count, 10, 64)
		if err != nil {
			return invalid()
		}
		suffix = strings.ToUpper(suffix)
		if _, exists := seen[suffix]; exists {
			return invalid()
		}
		seen[suffix] = struct{}{}
		if suffix == localSuffix {
			occurrences = n
		}
	}
	if scanner.Err() != nil || len(seen) == 0 {
		return invalid()
	}
	return occurrences, nil
}

func (c *PasswordClient) lookup(ctx context.Context, prefix, suffix string) (uint64, error) {
	if !validHex(suffix, 35) {
		return 0, &Error{Kind: BadRequest}
	}
	resp, err := c.getRange(ctx, prefix)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Unlike email breaches, a range 404 is an API error, not a negative match.
	if resp.StatusCode != http.StatusOK {
		return 0, statusError(resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	data, err := readResponse(ctx, resp, 2*1024*1024)
	if err != nil {
		return 0, err
	}
	defer clear(data)
	return matchRange(data, suffix)
}

type PasswordSource struct{ client *PasswordClient }

func NewPasswordSource(client *PasswordClient) (*PasswordSource, error) {
	if client == nil {
		return nil, fmt.Errorf("Pwned Passwords source requires a client")
	}
	return &PasswordSource{client: client}, nil
}
func (*PasswordSource) Name() string            { return "pwned-passwords" }
func (*PasswordSource) Type() models.SourceType { return models.SourceAPI }
func (s *PasswordSource) SearchPassword(ctx context.Context, password security.Secret, emit sources.Emit) error {
	defer password.Destroy()
	if emit == nil {
		return fmt.Errorf("Pwned Passwords source requires a result consumer")
	}
	start := time.Now()
	var prefix, suffix string
	err := password.Consume(func(value []byte) error { prefix, suffix = passwordSHA1(value); return nil })
	// Only the five-character prefix enters getRange. Plaintext has been cleared
	// in every shared handle before HTTP starts. The suffix stays local.
	var count uint64
	if err != nil {
		err = &Error{Kind: BadRequest}
	} else {
		count, err = s.client.lookup(ctx, prefix, suffix)
	}
	prefix = ""
	suffix = ""
	result := models.Result{
		Source: s.Name(), SourceType: s.Type(), TargetType: models.TargetPassword, Target: security.Redacted,
		SiteName: "Have I Been Pwned / Pwned Passwords", URL: "https://haveibeenpwned.com/Passwords",
		Duration: time.Since(start), Metadata: map[string]string{"method": "sha1-k-anonymity"},
	}
	if err != nil {
		result.Status = models.StatusError
		result.Error = err.Error()
		for k, v := range errorMetadata(err) {
			result.Metadata[k] = v
		}
	} else {
		result.Status = models.StatusNotFound
		if count > 0 {
			result.Status = models.StatusFound
			result.Confidence = 100
		}
		result.Metadata["pwned"] = strconv.FormatBool(count > 0)
		result.Metadata["occurrences"] = strconv.FormatUint(count, 10)
	}
	if consumerErr := emit(result.Normalized()); consumerErr != nil {
		return consumerErr
	}
	return err
}

var _ sources.Source = (*PasswordSource)(nil)
var _ sources.PasswordSearcher = (*PasswordSource)(nil)
