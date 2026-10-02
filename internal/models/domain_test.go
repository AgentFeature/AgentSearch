package models

import (
	"strings"
	"testing"
)

func TestDomainTarget(t *testing.T) {
	for _, value := range []string{" Example.COM. ", "www.example.com", "xn--bcher-kva.example"} {
		target, e := NewTarget(TargetDomain, value)
		if e != nil || !target.Valid() || target.Type() != TargetDomain || target.Value() != strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), ".")) {
			t.Fatal("valid domain rejected")
		}
	}
	for _, value := range []string{"", "localhost", "https://example.com", "example.com/path", "example.com:443", "user@example.com", "192.0.2.1", "::1", "*.example.com", "../example.com", "a..example", "-a.example", "a_.example", strings.Repeat("x", 64) + ".example", strings.Repeat("x", 254) + ".example"} {
		if _, e := NewDomainTarget(value); e == nil {
			t.Fatal("non-domain accepted")
		}
	}
}
