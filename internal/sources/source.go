// Package sources defines provider contracts independent of HTTP, workers and output.
package sources

import (
	"context"

	"github.com/AgentFeature/agentsearch/internal/models"
	"github.com/AgentFeature/agentsearch/internal/security"
)

// Source names are stable registry identifiers. Type describes provenance.
// Non-sensitive sources in one registry must be independent: invocations may
// overlap. Sources own their internal work and must finish it before returning.
type Source interface {
	Name() string
	Type() models.SourceType
}

// Emit provides streaming backpressure. A source must call it serially, stop
// when it returns an error, and not call it after its search method returns.
// Partial results are valid even when the search subsequently returns an error.
type Emit func(models.Result) error

type BitcoinTransactionSearcher interface {
	SearchBitcoinTransaction(context.Context, string, Emit) error
}

type BitcoinSearcher interface {
	SearchBitcoin(context.Context, string, Emit) error
}

type IPSearcher interface {
	SearchIP(context.Context, string, Emit) error
}

type DomainSearcher interface {
	SearchDomain(context.Context, string, Emit) error
}

type UsernameSearcher interface {
	SearchUsername(context.Context, string, Emit) error
}
type EmailSearcher interface {
	SearchEmail(context.Context, string, Emit) error
}

// PasswordSearcher receives a shared secret handle. Implementations may consume
// it once to derive local lookup material and clear plaintext before networking.
// A consuming password provider must not be followed by another plaintext consumer.
type PasswordSearcher interface {
	SearchPassword(context.Context, security.Secret, Emit) error
}
type PasswordHashSearcher interface {
	SearchPasswordHash(context.Context, security.Secret, Emit) error
}

// Capabilities derives support from implemented interfaces, so declarations
// cannot drift away from the operations actually provided.
func Capabilities(s Source) []models.TargetType {
	var out []models.TargetType
	if _, ok := s.(BitcoinTransactionSearcher); ok {
		out = append(out, models.TargetBitcoinTransaction)
	}
	if _, ok := s.(BitcoinSearcher); ok {
		out = append(out, models.TargetBitcoin)
	}
	if _, ok := s.(IPSearcher); ok {
		out = append(out, models.TargetIP)
	}
	if _, ok := s.(DomainSearcher); ok {
		out = append(out, models.TargetDomain)
	}
	if _, ok := s.(UsernameSearcher); ok {
		out = append(out, models.TargetUsername)
	}
	if _, ok := s.(EmailSearcher); ok {
		out = append(out, models.TargetEmail)
	}
	if _, ok := s.(PasswordSearcher); ok {
		out = append(out, models.TargetPassword)
	}
	if _, ok := s.(PasswordHashSearcher); ok {
		out = append(out, models.TargetPasswordHash)
	}
	return out
}
func Supports(s Source, kind models.TargetType) bool {
	for _, capability := range Capabilities(s) {
		if capability == kind {
			return true
		}
	}
	return false
}
