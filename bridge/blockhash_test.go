package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Expected value computed independently (Python): DER of
// SEQUENCE{INTEGER 1, OCTET STRING 32x0x01, OCTET STRING 32x0x02}, SHA-256.
func TestHeaderHashMatchesIndependentVector(t *testing.T) {
	got, err := headerHash(1, bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	const want = "8958d309221dff9175606e70d8b0f60d44326787f5375730953d3e4c7277894b"
	if hex.EncodeToString(got) != want {
		t.Fatalf("header hash %x, want %s", got, want)
	}
}
