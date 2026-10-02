package security

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	for _, tt := range []struct{ input, secret string }{
		{"password=hunter2", "hunter2"},
		{"api_key=keyvalue", "keyvalue"},
		{"Authorization: Bearer abc.def", "abc.def"},
		{"Proxy-Authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"},
		{"Get http://user:pass@proxy.example:80 failed", "user:pass"},
	} {
		t.Run(tt.input, func(t *testing.T) {
			if got := Redact(tt.input); strings.Contains(got, tt.secret) {
				t.Fatal(got)
			}
		})
	}
	if Redact("ordinary profile") != "ordinary profile" {
		t.Fatal("changed ordinary text")
	}
	if got := Redact("p%40ss p@ss", "p@ss"); strings.Contains(got, "ss") {
		t.Fatal(got)
	}
	fields := map[string]string{"X-API-Key": "secret", "Accept": "text/html"}
	if Fields(fields)["X-API-Key"] != Redacted || fields["X-API-Key"] != "secret" {
		t.Fatal("field redaction mutated input")
	}
}
func TestSecret(t *testing.T) {
	s := NewSecret("never-print-this")
	b, _ := json.Marshal(s)
	for _, v := range []string{fmt.Sprint(s), fmt.Sprintf("%+v %#v", s, s), string(b), s.LogValue().String()} {
		if strings.Contains(v, s.Reveal()) {
			t.Fatal(v)
		}
	}
}

func TestHIBPHeaderRedaction(t *testing.T) {
	fields := Fields(map[string]string{"hibp-api-key": "test-only-value", "HIBP_API_KEY": "another-test-value", "Authorization": "Bearer test-only-value"})
	for _, v := range fields {
		if v != Redacted {
			t.Fatal("sensitive header was not redacted")
		}
	}
	if got := Redact("hibp-api-key: test-only-value"); strings.Contains(got, "test-only-value") {
		t.Fatal("key-value diagnostic was not redacted")
	}
}
