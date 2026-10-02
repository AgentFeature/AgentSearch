package config

import "testing"

func TestDomainCLIConfiguration(t *testing.T) {
	cfg, e := ParseArgs([]string{"-domain", "Example.COM.", "-services", "operator.yaml", "-rt", "2s"})
	if e != nil || cfg.Mode != ModeDomain || cfg.Targets[0] != "example.com" || cfg.ServicesFile != "operator.yaml" {
		t.Fatal("domain flags not wired")
	}
	for _, args := range [][]string{{"-domain", ""}, {"-domain", "https://example.com"}, {"-domain", "example.com", "-email", "user@example.com"}, {"-domain", "example.com", "-u", "example"}, {"-domain", "example.com", "-password", "example-password"}, {"-domain", "example.com", "-rt", "0s"}, {"-domain", "example.com", "-password-backend", "api"}, {"-domain", "example.com", "-w", "2"}} {
		if _, e := ParseArgs(args); e == nil {
			t.Fatal("mixed/invalid domain options accepted")
		}
	}
}
