package models

import (
	"errors"
	"strings"
	"testing"
)

func TestBitcoinAddressVectors(t *testing.T) {
	// Witness vectors: BIP173/BIP350, bitcoin/bips. Base58 vectors: Bitcoin
	// genesis coinbase and BIP16's published P2SH example (not generated here).
	for _, tc := range []struct{ value, kind string }{
		{"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "p2pkh"},
		{"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "p2sh"},
		// Bitcoin Core src/test/data/key_io_valid.json mainnet P2WSH vector.
		{"bc1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwqhkdhv7", "p2wsh"},
		{"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "p2wpkh"},
		{"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "p2tr"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			a, k, err := BitcoinAddress(tc.value)
			if err != nil || k != tc.kind {
				t.Fatalf("%s %v", k, err)
			}
			if strings.HasPrefix(strings.ToLower(tc.value), "bc1") && a != strings.ToLower(tc.value) {
				t.Fatal("case normalization")
			}
			target, err := NewTarget(TargetBitcoin, " "+tc.value+" ")
			if err != nil || target.Type() != TargetBitcoin || target.Value() != a {
				t.Fatal("typed target")
			}
			if _, _, err := BitcoinAddress(tc.value[:len(tc.value)-1] + "!"); !errors.Is(err, ErrInvalidBitcoinAddress) {
				t.Fatal("bad checksum accepted")
			}
		})
	}
	invalid := []string{"", "bc1...", strings.Repeat("1", 101), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
		"bc1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
		"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
		"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
		"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
		"bc1pw5dgrnzv", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
		"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", "bc1gmk9yu"}
	for _, value := range invalid {
		if _, _, e := BitcoinAddress(value); !errors.Is(e, ErrInvalidBitcoinAddress) {
			t.Errorf("invalid vector accepted/classified incorrectly: %q: %v", value, e)
		}
	}
	for _, value := range []string{
		"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
		"mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
		"BC1SW50QGDZ25J", "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
		"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
		"https://example.com", "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	} {
		if _, _, e := BitcoinAddress(value); !errors.Is(e, ErrUnsupportedBitcoinAddress) {
			t.Errorf("unsupported vector: %q: %v", value, e)
		}
	}
}

func FuzzBitcoinAddress(f *testing.F) {
	f.Add("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
	f.Add("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
	f.Fuzz(func(t *testing.T, s string) {
		a, k, e := BitcoinAddress(s)
		if e == nil {
			b, l, e := BitcoinAddress(a)
			if e != nil || a != b || k != l || len(a) > 90 {
				t.Fatal("unstable normalization")
			}
		}
	})
}
