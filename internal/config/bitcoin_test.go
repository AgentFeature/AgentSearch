package config

import "testing"

func TestBitcoinCLI(t *testing.T) {
	const address = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"
	cfg, err := ParseArgs([]string{"-bitcoin", address, "-services", "operator.yaml", "-rt", "2s"})
	if err != nil || cfg.Mode != ModeBitcoin || cfg.Targets[0] != "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" || cfg.ServicesFile != "operator.yaml" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, extra := range [][]string{{"-ip", "8.8.8.8"}, {"-domain", "example.com"}, {"-email", "user@example.com"}, {"-u", "example"}, {"-f", "file"}, {"-password", "fixture"}, {"-password-backend", "api"}, {"-w", "2"}, {"-retries", "3"}, {"-rt", "0s"}, {"-tt", "0s"}, {"unexpected"}} {
		if _, err := ParseArgs(append([]string{"-bitcoin", address}, extra...)); err == nil {
			t.Fatalf("accepted conflicting options %v", extra)
		}
	}
	for _, value := range []string{"", "bc1...", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"} {
		if _, err := ParseArgs([]string{"-bitcoin", value}); err == nil {
			t.Fatal("accepted invalid address")
		}
	}
	cfg, err = ParseArgs([]string{"-u", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"})
	if err != nil || cfg.Mode != ModeWebsites {
		t.Fatal("legacy mode changed")
	}
}
