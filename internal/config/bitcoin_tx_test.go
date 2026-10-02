package config

import "testing"

func TestBitcoinTransactionCLI(t *testing.T) {
	const txid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cfg, err := ParseArgs([]string{"-bitcoin-tx", txid, "-services", "operator.yaml", "-rt", "2s"})
	if err != nil || cfg.Mode != ModeBitcoinTransaction || cfg.Targets[0] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" || cfg.ServicesFile != "operator.yaml" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, extra := range [][]string{{"-bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"}, {"-ip", "8.8.8.8"}, {"-domain", "example.com"}, {"-email", "user@example.com"}, {"-u", "example"}, {"-f", "file"}, {"-password", "fixture"}, {"-password-backend", "api"}, {"-w", "2"}, {"-retries", "3"}, {"-rt", "0s"}, {"-tt", "0s"}, {"unexpected"}} {
		if _, err := ParseArgs(append([]string{"-bitcoin-tx", txid}, extra...)); err == nil {
			t.Fatalf("accepted conflicting options %v", extra)
		}
	}
	for _, value := range []string{"", "bc1...", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"} {
		if _, err := ParseArgs([]string{"-bitcoin-tx", value}); err == nil {
			t.Fatal("accepted invalid txid")
		}
	}
	cfg, err = ParseArgs([]string{"-u", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"})
	if err != nil || cfg.Mode != ModeWebsites {
		t.Fatal("legacy mode changed")
	}
}
