package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/AgentFeature/agentsearch/internal/app"
	"github.com/AgentFeature/agentsearch/internal/models"
)

const MaxBodyBytes = 32 << 10

// decodeRequest clears its owned encoded buffers before returning to search.
// JSON/runtime string copies cannot be guaranteed erased. Never log the DTO/body.
func decodeRequest(raw []byte, analysisFlag ...*bool) (models.Target, error) {
	defer clear(raw)
	invalid := func() (models.Target, error) { return models.Target{}, app.ErrInvalidSearch }
	if !utf8.Valid(raw) {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return invalid()
	}
	fields := make(map[string]json.RawMessage, 3)
	defer func() {
		for _, v := range fields {
			clear(v)
		}
	}()
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return invalid()
		}
		name, ok := token.(string)
		if !ok || (name != "type" && name != "target" && name != "password" && name != "analysis") {
			return invalid()
		}
		if _, exists := fields[name]; exists {
			return invalid()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			clear(value)
			return invalid()
		}
		fields[name] = value
	}
	if _, e = d.Token(); e != nil {
		return invalid()
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return invalid()
	}
	if value, ok := fields["analysis"]; ok {
		if !bytes.Equal(bytes.TrimSpace(value), []byte("true")) && !bytes.Equal(bytes.TrimSpace(value), []byte("false")) {
			return invalid()
		}
		if len(analysisFlag) > 0 && analysisFlag[0] != nil {
			*analysisFlag[0] = bytes.Equal(bytes.TrimSpace(value), []byte("true"))
		}
	}
	var kind, value, password string
	if json.Unmarshal(fields["type"], &kind) != nil {
		return invalid()
	}
	if kind == "password" {
		if _, ok := fields["target"]; ok {
			return invalid()
		}
		if json.Unmarshal(fields["password"], &password) != nil || !validPasswordEscapes(fields["password"]) {
			return invalid()
		}
		owned := []byte(password)
		password = ""
		return app.NewSearchTarget(kind, "", owned)
	}
	if _, ok := fields["password"]; ok {
		return invalid()
	}
	if json.Unmarshal(fields["target"], &value) != nil {
		return invalid()
	}
	return app.NewSearchTarget(kind, value, nil)
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them rather
// than silently changing a submitted password. Escaped backslashes are skipped.
func validPasswordEscapes(raw []byte) bool {
	for i := 1; i < len(raw)-1; i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		value, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value < 0xD800 || value > 0xDBFF {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if e != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		i += 6
	}
	return true
}
