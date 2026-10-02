package models

import (
	"fmt"
	"net/netip"
	"strings"
)

// NewIPTarget canonicalizes one literal without DNS resolution or probing.
// Like domain/email input, surrounding whitespace is trimmed. Zones, networks,
// URLs and hostnames are not IP targets. IPv4-mapped IPv6 is canonicalized to IPv4.
func NewIPTarget(value string) (Target, error) {
	if len(value) > 64 {
		return Target{}, fmt.Errorf("invalid IP; provide one IPv4 or IPv6 address")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || ip.Zone() != "" {
		return Target{}, fmt.Errorf("invalid IP; provide one IPv4 or IPv6 address")
	}
	return Target{kind: TargetIP, value: ip.Unmap().String()}, nil
}
