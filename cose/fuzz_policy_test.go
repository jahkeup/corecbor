// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

// FuzzVerifyNeverPanics (027 Phase 2): every Unmarshal-then-verify path,
// with the header policy options set, returns an error or nil for any
// input; alg binding, crit processing and duplicate-label checks never
// panic.
func FuzzVerifyNeverPanics(f *testing.F) {
	addCOSESeeds(f)
	for _, h := range []string{
		// RFC 9052 C.1.3 (crit ["reserved"]).
		"D86284" + "56A2687265736572766564F40281687265736572766564" + "A0" +
			"54546869732069732074686520636F6E74656E742E" +
			"818343A10126A10442313158403FC54702AA56E1B2CB20284294C9106A63F91BAC658D69351210A031D8FC7C5FF3E4BE39445B1A3E83E1510D1ACA2F2E8A7C081C7645042B18ABA9D1FAD1BD9C",
		// cose-wg sign-fail-04 (alg "unknown").
		"D2844AA10167756E6B6E6F776EA10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36",
		"d28447a20127028118630040", // crit [99], label 99 absent
		"d28443a10127a1028103f640", // crit in the unprotected bucket
		"d28443a10127a10127f640",   // alg in both buckets
	} {
		b, _ := hex.DecodeString(h)
		f.Add(b)
	}

	edPriv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	edV, _ := NewVerifier(edPriv.Public(), WithKnownCriticalHeaders("reserved", 99))
	macKey := make([]byte, 32)
	aesKey := make([]byte, 16)
	nonce := make([]byte, 12)
	kw := &AESKWKey{Key: aesKey}

	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := UnmarshalSign1(data); err == nil {
			_ = edV.Verify(m)
			_ = edV.VerifyDetached(m, nil)
		}
		if m, err := UnmarshalSign(data); err == nil {
			_, _ = VerifyMulti(m, []*Verifier{edV})
		}
		if m, err := UnmarshalMac0(data); err == nil {
			_ = VerifyMAC0(m, macKey, AlgHMAC256, WithMACKnownCriticalHeaders(99))
		}
		if m, err := UnmarshalMac(data); err == nil {
			for i := range m.Recipients {
				_ = VerifyMACMulti(m, kw, i, WithMACAlgorithms(AlgHMAC256_64, AlgHMAC256))
			}
		}
		if m, err := UnmarshalEncrypt0(data); err == nil {
			_, _ = DecryptEncrypt0(m, aesKey, nonce, AlgA128GCM)
		}
		if m, err := UnmarshalEncrypt(data); err == nil {
			for i := range m.Recipients {
				_, _ = DecryptMulti(m, kw, i, WithEncryptKnownCriticalHeaders(99))
			}
		}
	})
}
