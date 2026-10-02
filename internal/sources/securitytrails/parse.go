package securitytrails

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"

	"github.com/AgentFeature/agentsearch/internal/models"
)

const maxRecords = 2048

func parseDomain(raw []byte, expected string) (*domainData, error) {
	invalid := func() (*domainData, error) { return nil, &Error{Kind: "invalid_response", StatusCode: 200} }
	var wire domainWire
	if json.Unmarshal(raw, &wire) != nil || wire.DNS == nil {
		return invalid()
	}
	host, err := models.NewDomainTarget(wire.Hostname)
	if err != nil || host.Value() != expected {
		return invalid()
	}
	result := &domainData{}
	// Fixed family order and sorting make output independent of map/response order.
	for _, kind := range []string{"a", "aaaa", "mx", "ns"} {
		data, exists := wire.DNS[kind]
		if !exists || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			continue
		}
		var set recordSet
		if json.Unmarshal(data, &set) != nil || set.Values == nil || len(result.records)+len(set.Values) > maxRecords {
			return invalid()
		}
		for _, value := range set.Values {
			record := dnsRecord{kind: "dns_" + kind}
			switch kind {
			case "a", "aaaa":
				var field addressWire
				if json.Unmarshal(value, &field) != nil {
					return invalid()
				}
				ip, e := netip.ParseAddr(field.IP)
				if e != nil || ip.Zone() != "" || (kind == "a" && !ip.Is4()) || (kind == "aaaa" && (!ip.Is6() || ip.Is4In6())) {
					return invalid()
				}
				record.value = ip.String()
			case "mx":
				var field mxWire
				if json.Unmarshal(value, &field) != nil || field.Priority == nil || *field.Priority < 0 || *field.Priority > 65535 {
					return invalid()
				}
				// RFC 7505 null MX denotes no mail service, not a negative domain lookup.
				if field.Host == "." && *field.Priority == 0 {
					record.value = "0 ."
					break
				}
				target, e := models.NewDomainTarget(field.Host)
				if e != nil {
					return invalid()
				}
				record.value = strconv.Itoa(*field.Priority) + " " + target.Value()
			case "ns":
				var field nsWire
				if json.Unmarshal(value, &field) != nil {
					return invalid()
				}
				target, e := models.NewDomainTarget(field.Nameserver)
				if e != nil {
					return invalid()
				}
				record.value = target.Value()
			}
			result.records = append(result.records, record)
		}
	}
	sort.Slice(result.records, func(i, j int) bool {
		a, b := result.records[i], result.records[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.value < b.value
	})
	return result, nil
}
