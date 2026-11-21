// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import "fmt"

// recipientAlg is the algorithm a deriver's COSE_Recipient carries:
// its own Algorithm(), except PBES2 under WithLegacyPBES2Labels (-11).
func recipientAlg(r KeyDeriver, legacy legacyEncoding) Algorithm {
	if _, ok := r.(*PBES2Key); ok && legacy.pbes2 {
		return AlgPBES2_HS256_A128KW
	}
	return r.Algorithm()
}

// newRecipientLayer returns a recipient's protected bucket holding alg,
// and its encoding (the KDF context's "protected", RFC 9053 §5.2).
func newRecipientLayer(alg Algorithm) (Headers, []byte, error) {
	var h Headers
	h.SetAlgorithm(alg)
	b, err := h.encodeProtected()
	if err != nil {
		return Headers{}, nil, err
	}
	h.raw = b
	return h, b, nil
}

// directAgreement reports whether recipients is a single direct key
// agreement recipient (RFC 9052 §8.5.4), whose agreed key must be used
// as the content key. More recipients with one of them direct is an
// error: a direct recipient can't carry a randomly generated key.
func directAgreement(recipients []KeyDeriver, legacy legacyEncoding) (KeyAgreer, bool, error) {
	direct := -1
	for i, r := range recipients {
		ka, ok := r.(KeyAgreer)
		if !ok || !isDirectKeyAgreement(r.Algorithm()) {
			continue
		}
		if _, isECDH := r.(*ECDHESKey); isECDH && legacy.ecdh && r.Algorithm() == AlgECDH_ES_HKDF_256 {
			continue // v0.2 -25 wraps a random CEK
		}
		if len(recipients) > 1 {
			return nil, false, fmt.Errorf("%w: recipient %d uses direct key agreement (%s) and must be the only recipient", ErrInvalidKey, i, r.Algorithm())
		}
		direct = i
		_ = ka
	}
	if direct < 0 {
		return nil, false, nil
	}
	return recipients[direct].(KeyAgreer), true, nil
}

// sealRecipients builds one COSE_Recipient per deriver for cek. When
// agreed is non-nil, it is the single direct-agreement recipient whose
// headers came from AgreeKey.
func sealRecipients(cek []byte, contentAlg Algorithm, recipients []KeyDeriver, legacy legacyEncoding) ([]Recipient, error) {
	out := make([]Recipient, len(recipients))
	for i, r := range recipients {
		prot, protBytes, err := newRecipientLayer(recipientAlg(r, legacy))
		if err != nil {
			return nil, err
		}
		ciphertext, headers, err := r.WrapKey(cek, KeyWrapOpts{
			CEKAlgorithm: contentAlg, CEKLength: len(cek),
			protected: protBytes, legacy: legacy,
		})
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		out[i] = Recipient{Protected: prot, Unprotected: headers, Ciphertext: ciphertext}
	}
	return out, nil
}

// agreeRecipient runs direct key agreement for the single recipient and
// returns the content key and the COSE_Recipient.
func agreeRecipient(ka KeyAgreer, contentAlg Algorithm, keyLen int) ([]byte, Recipient, error) {
	alg := ka.(KeyDeriver).Algorithm()
	prot, protBytes, err := newRecipientLayer(alg)
	if err != nil {
		return nil, Recipient{}, err
	}
	cek, headers, err := ka.AgreeKey(KeyWrapOpts{CEKAlgorithm: contentAlg, CEKLength: keyLen, protected: protBytes})
	if err != nil {
		return nil, Recipient{}, fmt.Errorf("recipient 0: %w", err)
	}
	return cek, Recipient{Protected: prot, Unprotected: headers}, nil
}

// openRecipient recovers the content key from r with deriver. The
// recipient's alg must be the deriver's: an alg that doesn't match would
// otherwise be processed as the deriver's algorithm (proposal 027 H2).
// The legacy PBES2 identifiers are accepted only under
// WithLegacyPBES2Labels.
func openRecipient(r *Recipient, deriver KeyDeriver, contentAlg Algorithm, keyLen int, o *encryptOpts) ([]byte, error) {
	if err := checkCrit(&r.Protected, &r.Unprotected, &o.policy); err != nil {
		return nil, err
	}
	if !o.policy.legacyAlg {
		a, loc, err := headerAlg(&r.Protected, &r.Unprotected)
		if err != nil {
			return nil, err
		}
		want := recipientAlg(deriver, o.legacy)
		if loc != algAbsent && a != want {
			if a == AlgPBES2_HS256_A128KW && !o.legacy.pbes2 {
				return nil, fmt.Errorf("%w: recipient alg -11 (v0.2 PBES2 encoding; see WithLegacyPBES2Labels)", ErrUnsupportedAlgorithm)
			}
			return nil, fmt.Errorf("%w: recipient alg %s, key implies %s", ErrAlgorithmMismatch, a, want)
		}
	}
	protBytes, err := r.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	// UnwrapKey's errors pass through unchanged, as in v0.2.2.
	return deriver.UnwrapKey(r.Ciphertext, r.Unprotected, KeyUnwrapOpts{
		CEKAlgorithm: contentAlg, CEKLength: keyLen,
		protected: protBytes, legacy: o.legacy,
	})
}
