// Package bitcoinlabels performs one WalletExplorer address association lookup.
// Provider labels are external observations, never verified ownership claims.
package bitcoinlabels

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/security"
)

const (
	MaxResponseBytes   = 256 << 10
	MaxLabels          = 1 // The address-lookup contract has one scalar label, not a list.
	MaxLabelBytes      = 256
	MaxIdentifiers     = 1
	MaxIdentifierBytes = 64
)

type association struct {
	Label    string `json:"label,omitempty"`
	Category string `json:"category,omitempty"`
	WalletID string `json:"provider_wallet_id,omitempty"`
}

func safeText(s string, maxBytes int) bool {
	if len(s) > maxBytes || !utf8.ValidString(s) || security.Redact(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// parse accepts exactly one object, rejecting duplicate keys, null required
// fields and unknown nested schemas. Unknown scalar fields never enter evidence.
// updated_to_block describes provider chain coverage, NOT label freshness.
func parse(raw []byte) (association, error) {
	bad := func() (association, error) { return association{}, &failure{kind: "invalid_response"} }
	unsupported := func() (association, error) { return association{}, &failure{kind: "unsupported_response"} }
	if len(raw) > MaxResponseBytes || !utf8.Valid(raw) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return bad()
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return bad()
		}
		name, ok := key.(string)
		if !ok {
			return bad()
		}
		if _, ok = fields[name]; ok {
			return bad()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return bad()
		}
		fields[name] = value
		if len(fields) > 32 {
			return unsupported()
		}
	}
	if _, err = d.Token(); err != nil {
		return bad()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return bad()
	}
	for key, value := range fields {
		switch key {
		case "found", "error", "label", "wallet_id", "category", "updated_to_block":
			continue
		}
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			return unsupported()
		}
	}
	var found *bool
	if value, ok := fields["found"]; ok && json.Unmarshal(value, &found) != nil {
		return bad()
	}
	if value, ok := fields["error"]; ok {
		var text string
		if json.Unmarshal(value, &text) != nil || !safeText(text, MaxLabelBytes) || text == "" || found != nil && *found {
			return bad()
		}
		return association{}, &failure{kind: "provider_error"}
	}
	if found == nil {
		return bad()
	}
	var a association
	for _, field := range []struct {
		key  string
		dest *string
		max  int
	}{{"label", &a.Label, MaxLabelBytes}, {"category", &a.Category, MaxLabelBytes}, {"wallet_id", &a.WalletID, MaxIdentifierBytes}} {
		if value, ok := fields[field.key]; ok {
			value = bytes.TrimSpace(value)
			if len(value) > 0 && (value[0] == '[' || value[0] == '{') {
				return unsupported()
			}
			if bytes.Equal(value, []byte("null")) || json.Unmarshal(value, field.dest) != nil || !safeText(*field.dest, field.max) {
				return bad()
			}
			if *field.dest != "" && strings.TrimSpace(*field.dest) == "" {
				return bad()
			}
		}
	}
	if value, ok := fields["updated_to_block"]; ok {
		var height *int64
		if json.Unmarshal(value, &height) != nil || height == nil || *height < 0 || *height > 2147483647 {
			return bad()
		}
	}
	if !*found {
		if a != (association{}) {
			return bad()
		}
		return a, nil // Provider-scoped negative, not global absence of associations.
	}
	if a.WalletID == "" {
		return bad()
	}
	for _, c := range a.WalletID {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return bad()
		}
	}
	a.WalletID = strings.ToLower(a.WalletID)
	if a.Label == "" && a.Category != "" {
		return unsupported()
	}
	return a, nil // A cluster identifier without a label is not a named entity.
}
