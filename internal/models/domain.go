package models

import (
	"fmt"
	"net/netip"
	"strings"
)

// NewDomainTarget accepts a DNS hostname, not a URL, IP or search expression.
// ASCII/punycode input is canonicalized without DNS resolution. It does not
// certify registration, public reachability, ownership or a recognized suffix.
func NewDomainTarget(value string) (Target, error) {
	invalid := func() (Target, error) {
		return Target{}, fmt.Errorf("invalid domain; use a bare ASCII/punycode hostname")
	}
	if len(value) > 255 {
		return invalid()
	}
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(value) == 0 || len(value) > 253 {
		return invalid()
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return invalid()
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return invalid()
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid()
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return invalid()
			}
		}
	}
	hasLetter := false
	for _, c := range labels[len(labels)-1] {
		if c >= 'a' && c <= 'z' {
			hasLetter = true
		}
	}
	if !hasLetter {
		return invalid()
	}
	return Target{kind: TargetDomain, value: value}, nil
}
