// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"fmt"
	"maps"
)

// recipientAlg is the algorithm a deriver's COSE_Recipient carries:
// its own Algorithm(), except PBES2 under WithLegacyPBES2Labels (-11).
func recipientAlg(r KeyDeriver, legacy legacyEncoding) Algorithm {
	if _, ok := r.(*PBES2Key); ok && legacy.pbes2 {
		return AlgPBES2_HS256_A128KW
	}
	return r.Algorithm()
}

// emptyProtectedRecipient reports whether a recipient with alg must have
// an empty protected bucket, with alg unprotected: direct encryption
// (RFC 9052 §8.5.1) and AE key wrap, AES-KW and PBES2 (§8.5.2, §5.4).
// The v0.2 PBES2 identifier (-11) keeps v0.2's layout.
func emptyProtectedRecipient(alg Algorithm) bool {
	switch alg {
	case AlgDirect, AlgA128KW, AlgA192KW, AlgA256KW, AlgPrivatePBES2_HS256_A128KW:
		return true
	default:
		return false
	}
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

// recipientLayerer is implemented by derivers whose COSE_Recipient
// protected bucket carries more than alg (HPKERecipient adds kid).
type recipientLayerer interface {
	recipientLayer(alg Algorithm) (Headers, []byte, error)
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

// directEncryption handles a direct-encryption recipient (alg direct,
// RFC 9052 §8.5.1): its shared key is the content key, so it must be the
// only recipient. ok is false when no recipient is direct. The returned
// COSE_Recipient has an empty protected bucket, alg in the unprotected
// bucket and a zero-length ciphertext, as §8.5.1 requires.
func directEncryption(recipients []KeyDeriver, contentAlg Algorithm, keyLen int) (cek []byte, r Recipient, ok bool, err error) {
	for i, d := range recipients {
		if d.Algorithm() != AlgDirect {
			continue
		}
		if len(recipients) > 1 {
			return nil, Recipient{}, false, fmt.Errorf("%w: recipient %d uses direct encryption and must be the only recipient (RFC 9052 §8.5.1)", ErrInvalidKey, i)
		}
		cek, err = d.UnwrapKey(nil, Headers{}, KeyUnwrapOpts{CEKAlgorithm: contentAlg, CEKLength: keyLen, seal: true})
		if err != nil {
			return nil, Recipient{}, false, fmt.Errorf("recipient 0: %w", err)
		}
		if len(cek) == 0 {
			return nil, Recipient{}, false, fmt.Errorf("%w: recipient 0: direct key is empty", ErrInvalidKey)
		}
		var u Headers
		u.SetAlgorithm(AlgDirect)
		return cek, Recipient{Unprotected: u, Ciphertext: []byte{}}, true, nil
	}
	return nil, Recipient{}, false, nil
}

// sealRecipients builds one COSE_Recipient per deriver for cek. When
// agreed is non-nil, it is the single direct-agreement recipient whose
// headers came from AgreeKey.
func sealRecipients(cek []byte, contentAlg Algorithm, recipients []KeyDeriver, legacy legacyEncoding) ([]Recipient, error) {
	out := make([]Recipient, len(recipients))
	for i, r := range recipients {
		if err := checkHPKEKeyMix(r, legacy); err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		alg := recipientAlg(r, legacy)
		if emptyProtectedRecipient(alg) {
			ciphertext, headers, err := r.WrapKey(cek, KeyWrapOpts{
				CEKAlgorithm: contentAlg, CEKLength: len(cek), legacy: legacy,
			})
			if err != nil {
				return nil, fmt.Errorf("recipient %d: %w", i, err)
			}
			params := maps.Clone(headers.params)
			if params == nil {
				params = make(map[any]any, 1)
			}
			if _, ok := params[headerLabelAlgorithm]; !ok {
				params[headerLabelAlgorithm] = int64(alg)
			}
			out[i] = Recipient{Unprotected: Headers{params: params}, Ciphertext: ciphertext}
			continue
		}
		var prot Headers
		var protBytes []byte
		var err error
		if l, ok := r.(recipientLayerer); ok {
			prot, protBytes, err = l.recipientLayer(recipientAlg(r, legacy))
		} else {
			prot, protBytes, err = newRecipientLayer(recipientAlg(r, legacy))
		}
		if err != nil {
			return nil, err
		}
		ciphertext, headers, err := r.WrapKey(cek, KeyWrapOpts{
			CEKAlgorithm: contentAlg, CEKLength: len(cek),
			protected: string(protBytes), legacy: legacy,
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
	cek, headers, err := ka.AgreeKey(KeyWrapOpts{CEKAlgorithm: contentAlg, CEKLength: keyLen, protected: string(protBytes)})
	if err != nil {
		return nil, Recipient{}, fmt.Errorf("recipient 0: %w", err)
	}
	return cek, Recipient{Protected: prot, Unprotected: headers}, nil
}

// openRecipient recovers the content key from r with deriver. The
// recipient's alg must be present (RFC 9052 §8.5, proposal 037 S9) and
// be the deriver's: an alg that doesn't match would
// otherwise be processed as the deriver's algorithm (proposal 027 H2).
// The legacy PBES2 identifiers are accepted only under
// WithLegacyPBES2Labels.
func openRecipient(r *Recipient, deriver KeyDeriver, contentAlg Algorithm, keyLen int, o *encryptOpts) ([]byte, error) {
	if err := checkHPKEKeyMix(deriver, o.legacy); err != nil {
		return nil, err
	}
	if err := checkCrit(&r.Protected, &r.Unprotected, &o.policy); err != nil {
		return nil, err
	}
	if !o.policy.legacyAlg {
		a, loc, err := headerAlg(&r.Protected, &r.Unprotected)
		if err != nil {
			return nil, err
		}
		want := recipientAlg(deriver, o.legacy)
		if loc == algAbsent {
			// RFC 9052 §8.5: every recipient class carries alg.
			return nil, fmt.Errorf("%w: recipient has no alg header (RFC 9052 §8.5)", ErrAlgorithmMismatch)
		}
		if a != want {
			if a == AlgPBES2_HS256_A128KW && !o.legacy.pbes2 {
				return nil, fmt.Errorf("%w: recipient alg -11 (v0.2 PBES2 encoding; see WithLegacyPBES2Labels, WithLegacyMACPBES2Labels)", ErrUnsupportedAlgorithm)
			}
			return nil, fmt.Errorf("%w: recipient alg %s, key implies %s", ErrAlgorithmMismatch, a, want)
		}
	}
	if emptyProtectedRecipient(recipientAlg(deriver, o.legacy)) && !r.Protected.IsEmpty() && !o.allowProtRecipient {
		return nil, fmt.Errorf("%w: a %s recipient's protected bucket must be empty (RFC 9052 §5.4, §8.5; see AllowProtectedRecipientHeaders, AllowMACProtectedRecipientHeaders)", ErrMalformed, deriver.Algorithm())
	}
	if deriver.Algorithm() == AlgDirect && len(r.Ciphertext) != 0 {
		return nil, fmt.Errorf("%w: direct recipient ciphertext must be empty (RFC 9052 §8.5.1)", ErrDecryption)
	}
	protBytes, err := r.Protected.authProtected(&o.policy)
	if err != nil {
		return nil, err
	}
	// UnwrapKey's errors pass through unchanged, as in v0.2.2.
	return deriver.UnwrapKey(r.Ciphertext, r.Unprotected, KeyUnwrapOpts{
		CEKAlgorithm: contentAlg, CEKLength: keyLen,
		protected: string(protBytes), legacy: o.legacy,
	})
}
