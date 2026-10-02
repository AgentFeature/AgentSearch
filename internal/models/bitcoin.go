package models

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"
)

var ErrInvalidBitcoinAddress = errors.New("invalid Bitcoin address")
var ErrUnsupportedBitcoinAddress = errors.New("unsupported Bitcoin address format or network")

// BitcoinAddress validates Base58Check and BIP173/BIP350 witness encodings.
// Only mainnet P2PKH, P2SH, P2WPKH, P2WSH and P2TR are supported. It does
// not establish activity, ownership, or the spendability of an address.
func BitcoinAddress(value string) (address, kind string, err error) {
	if len(value) > 100 {
		return "", "", ErrInvalidBitcoinAddress
	}
	s := strings.TrimSpace(value)
	if len(s) < 8 || len(s) > 90 {
		return "", "", ErrInvalidBitcoinAddress
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "bc1") || strings.HasPrefix(lower, "tb1") || strings.HasPrefix(lower, "bcrt1") {
		if s != lower && s != strings.ToUpper(s) {
			return "", "", ErrInvalidBitcoinAddress
		}
		pos := strings.LastIndexByte(lower, '1')
		hrp := lower[:pos]
		data := make([]byte, 0, len(s))
		for _, c := range []byte(lower[pos+1:]) {
			n := strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", c)
			if n < 0 {
				return "", "", ErrInvalidBitcoinAddress
			}
			data = append(data, byte(n))
		}
		if len(data) < 7 {
			return "", "", ErrInvalidBitcoinAddress
		}
		var expanded []byte
		for _, c := range []byte(hrp) {
			expanded = append(expanded, c>>5)
		}
		expanded = append(expanded, 0)
		for _, c := range []byte(hrp) {
			expanded = append(expanded, c&31)
		}
		check := bitcoinPolymod(append(expanded, data...))
		version := data[0]
		if version > 16 || (version == 0 && check != 1) || (version != 0 && check != 0x2bc830a3) {
			return "", "", ErrInvalidBitcoinAddress
		}
		var acc uint32
		bits, size := 0, 0
		for _, n := range data[1 : len(data)-6] {
			acc = (acc<<5 | uint32(n)) & 0xfff
			bits += 5
			if bits >= 8 {
				bits -= 8
				size++
			}
		}
		if bits >= 5 || ((acc<<(8-bits))&255) != 0 || size < 2 || size > 40 {
			return "", "", ErrInvalidBitcoinAddress
		}
		if version == 0 && size != 20 && size != 32 {
			return "", "", ErrInvalidBitcoinAddress
		}
		if hrp != "bc" {
			return "", "", ErrUnsupportedBitcoinAddress
		}
		switch {
		case version == 0 && size == 20:
			kind = "p2wpkh"
		case version == 0 && size == 32:
			kind = "p2wsh"
		case version == 1 && size == 32:
			kind = "p2tr"
		default:
			return "", "", ErrUnsupportedBitcoinAddress
		}
		return lower, kind, nil
	}
	if !strings.ContainsRune("123mn", rune(s[0])) {
		return "", "", ErrUnsupportedBitcoinAddress
	}
	if len(s) < 26 || len(s) > 35 {
		return "", "", ErrInvalidBitcoinAddress
	}
	n := new(big.Int)
	for _, c := range []byte(s) {
		digit := strings.IndexByte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", c)
		if digit < 0 {
			return "", "", ErrInvalidBitcoinAddress
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(digit)))
	}
	raw := n.Bytes()
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	raw = append(make([]byte, zeros), raw...)
	if len(raw) != 25 {
		return "", "", ErrInvalidBitcoinAddress
	}
	first := sha256.Sum256(raw[:21])
	second := sha256.Sum256(first[:])
	if !bytes.Equal(raw[21:], second[:4]) {
		return "", "", ErrInvalidBitcoinAddress
	}
	switch raw[0] {
	case 0:
		kind = "p2pkh"
	case 5:
		kind = "p2sh"
	default:
		return "", "", ErrUnsupportedBitcoinAddress
	}
	return s, kind, nil
}

func bitcoinPolymod(values []byte) uint32 {
	chk := uint32(1)
	generators := [...]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range generators {
			if (top>>i)&1 != 0 {
				chk ^= g
			}
		}
	}
	return chk
}

func NewBitcoinTarget(value string) (Target, error) {
	address, _, err := BitcoinAddress(value)
	if err != nil {
		return Target{}, err
	}
	return Target{kind: TargetBitcoin, value: address}, nil
}
