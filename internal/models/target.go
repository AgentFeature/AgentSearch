package models

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"unicode"

	"github.com/AgentFeature/agentsearch/internal/security"
)

type TargetType string

const (
	TargetBitcoinTransaction TargetType = "bitcoin_tx"
	TargetBitcoin            TargetType = "bitcoin"
	TargetIP                 TargetType = "ip"
	TargetDomain             TargetType = "domain"
	TargetUsername           TargetType = "username"
	TargetEmail              TargetType = "email"
	TargetPassword           TargetType = "password"
	TargetPasswordHash       TargetType = "password_hash"
)

func (t TargetType) Valid() bool {
	switch t {
	case TargetUsername, TargetEmail, TargetPassword, TargetPasswordHash, TargetDomain, TargetIP, TargetBitcoin, TargetBitcoinTransaction:
		return true
	}
	return false
}
func (t TargetType) Sensitive() bool { return t == TargetPassword || t == TargetPasswordHash }

// Target is input, never a result payload. Private fields prevent accidentally
// serializing a raw password or changing its type after construction.
type Target struct {
	kind   TargetType
	value  string
	secret security.Secret
}

func NewTarget(kind TargetType, value string) (Target, error) {
	if kind == TargetBitcoinTransaction {
		return NewBitcoinTransactionTarget(value)
	}
	if kind == TargetBitcoin {
		return NewBitcoinTarget(value)
	}
	if kind == TargetIP {
		return NewIPTarget(value)
	}
	if kind == TargetDomain {
		return NewDomainTarget(value)
	}
	if !kind.Valid() {
		return Target{}, fmt.Errorf("unsupported target type")
	}
	if value == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if kind.Sensitive() {
		return NewSensitiveTarget(kind, security.NewSecret(value))
	}
	return Target{kind: kind, value: value}, nil
}

// LegacyTarget preserves -u/-f string substitution, including email-like inputs.
// It is deliberately not a strict email validator.
func LegacyTarget(value string) (Target, error) {
	kind := TargetUsername
	if strings.Contains(value, "@") {
		kind = TargetEmail
	}
	return NewTarget(kind, value)
}
func (t Target) Type() TargetType { return t.kind }

// Value explicitly accesses input. Only search implementations should need it.
func (t Target) Value() string {
	if t.kind.Sensitive() {
		return t.secret.Reveal()
	}
	return t.value
}

// Secret returns a shared handle, avoiding plaintext copies during dispatch.
func (t Target) Secret() security.Secret { return t.secret }
func NewSensitiveTarget(kind TargetType, secret security.Secret) (Target, error) {
	if !kind.Sensitive() || secret.Empty() {
		return Target{}, fmt.Errorf("invalid sensitive target")
	}
	return Target{kind: kind, secret: secret}, nil
}
func (t Target) Valid() bool {
	if t.kind.Sensitive() {
		return !t.secret.Empty()
	}
	return t.kind.Valid() && t.value != ""
}
func (t Target) String() string {
	if t.kind.Sensitive() {
		return security.Redacted
	}
	return t.value
}
func (t Target) GoString() string     { return t.String() }
func (t Target) LogValue() slog.Value { return slog.StringValue(t.String()) }
func (t Target) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  TargetType `json:"type"`
		Value string     `json:"value"`
	}{t.kind, t.String()})
}
func (t Target) MarshalYAML() (any, error) {
	return struct {
		Type  TargetType `yaml:"type"`
		Value string     `yaml:"value"`
	}{t.kind, t.String()}, nil
}

// NewEmailTarget accepts a single bare address, trims surrounding whitespace,
// and preserves its case and plus tags. Display names and internal whitespace
// are intentionally unsupported. This does not check deliverability.
func NewEmailTarget(value string) (Target, error) {
	value = strings.TrimSpace(value)
	invalid := func() (Target, error) {
		return Target{}, fmt.Errorf("invalid email address; provide one bare address without a display name")
	}
	if value == "" || len(value) > 254 || strings.ContainsAny(value, "<>") {
		return invalid()
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return invalid()
		}
	}
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value || address.Name != "" {
		return invalid()
	}
	return NewTarget(TargetEmail, value)
}
