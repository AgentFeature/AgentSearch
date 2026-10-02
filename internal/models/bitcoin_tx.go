package models

import (
	"encoding/hex"
	"errors"
	"strings"
)

// NewBitcoinTransactionTarget trims surrounding whitespace like other typed
// targets, rejects internal whitespace, and canonicalizes hexadecimal case.
// It validates an identifier, not transaction existence or chain membership.
func NewBitcoinTransactionTarget(value string) (Target, error) {
	if len(value) > 128 {
		return Target{}, errors.New("invalid Bitcoin transaction ID")
	}
	value = strings.TrimSpace(value)
	if len(value) != 64 {
		return Target{}, errors.New("invalid Bitcoin transaction ID")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return Target{}, errors.New("invalid Bitcoin transaction ID")
	}
	return Target{kind: TargetBitcoinTransaction, value: strings.ToLower(value)}, nil
}
