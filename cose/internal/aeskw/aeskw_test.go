// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package aeskw

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestWrap_RFC3394Vectors(t *testing.T) {
	tests := []struct {
		name string
		kek  string
		data string
		want string
	}{
		{
			name: "128-bit KEK, 128-bit data",
			kek:  "000102030405060708090A0B0C0D0E0F",
			data: "00112233445566778899AABBCCDDEEFF",
			want: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			name: "192-bit KEK, 128-bit data",
			kek:  "000102030405060708090A0B0C0D0E0F1011121314151617",
			data: "00112233445566778899AABBCCDDEEFF",
			want: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			name: "256-bit KEK, 192-bit data",
			kek:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			data: "00112233445566778899AABBCCDDEEFF0001020304050607",
			want: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := mustHex(tt.kek)
			data := mustHex(tt.data)
			want := mustHex(tt.want)

			got, err := Wrap(kek, data)
			if err != nil {
				t.Fatalf("Wrap() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Wrap() = %X, want %X", got, want)
			}
		})
	}
}

func TestUnwrap_RFC3394Vectors(t *testing.T) {
	tests := []struct {
		name       string
		kek        string
		ciphertext string
		want       string
	}{
		{
			name:       "128-bit KEK, 128-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F",
			ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
			want:       "00112233445566778899AABBCCDDEEFF",
		},
		{
			name:       "192-bit KEK, 128-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F1011121314151617",
			ciphertext: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
			want:       "00112233445566778899AABBCCDDEEFF",
		},
		{
			name:       "256-bit KEK, 192-bit data",
			kek:        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			ciphertext: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
			want:       "00112233445566778899AABBCCDDEEFF0001020304050607",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kek := mustHex(tt.kek)
			ciphertext := mustHex(tt.ciphertext)
			want := mustHex(tt.want)

			got, err := Unwrap(kek, ciphertext)
			if err != nil {
				t.Fatalf("Unwrap() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("Unwrap() = %X, want %X", got, want)
			}
		})
	}
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	kek := mustHex("000102030405060708090A0B0C0D0E0F")
	data := mustHex("00112233445566778899AABBCCDDEEFF")

	wrapped, err := Wrap(kek, data)
	if err != nil {
		t.Fatalf("Wrap() error = %v", err)
	}

	unwrapped, err := Unwrap(kek, wrapped)
	if err != nil {
		t.Fatalf("Unwrap() error = %v", err)
	}

	if !bytes.Equal(unwrapped, data) {
		t.Errorf("round trip failed: got %X, want %X", unwrapped, data)
	}
}

func TestWrap_InvalidInput(t *testing.T) {
	kek := mustHex("000102030405060708090A0B0C0D0E0F")

	if _, err := Wrap(kek, []byte{1, 2, 3}); err == nil {
		t.Error("expected error for non-multiple-of-8 input")
	}

	if _, err := Wrap(kek, []byte{1, 2, 3, 4, 5, 6, 7, 8}); err == nil {
		t.Error("expected error for too-short input (8 bytes, need 16)")
	}
}

func TestUnwrap_IntegrityCheck(t *testing.T) {
	kek := mustHex("000102030405060708090A0B0C0D0E0F")
	ciphertext := mustHex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")

	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[0] ^= 0xFF

	if _, err := Unwrap(kek, corrupted); err == nil {
		t.Error("expected integrity check failure")
	}
}
