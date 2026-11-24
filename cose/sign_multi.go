// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"context"
	"fmt"

	"github.com/jahkeup/corecbor"
)

// SignMulti signs payload into a COSE_Sign with one signature per
// signer. Each signature carries its signer's headers. opts apply to the
// message body: WithProtectedHeaders and WithUnprotectedHeaders set the
// body headers, and WithSignerExternalData sets the external AAD for
// every signature (otherwise each signer's own is used). v0.2.2 accepted
// and ignored opts; calls without opts are unchanged.
func SignMulti(payload []byte, signers []*Signer, opts ...SignerOption) (*Sign, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: at least one signer required", ErrInvalidKey)
	}
	var body Signer
	for _, o := range opts {
		o(&body)
	}
	if err := checkBucketOverlap(body.protected, body.unprotected); err != nil {
		return nil, err
	}
	if _, err := headerParamsToMap(body.unprotected); err != nil {
		return nil, err
	}

	msg := &Sign{
		Protected:   Headers{params: body.protected},
		Unprotected: Headers{params: body.unprotected},
		Payload:     payload,
		Signatures:  make([]Signature, len(signers)),
	}

	bodyProtectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	msg.Protected.raw = bodyProtectedBytes

	for i, signer := range signers {
		sig, err := computeSignature(signer, bodyProtectedBytes, payload, body.external)
		if err != nil {
			return nil, fmt.Errorf("signer %d: %w", i, err)
		}
		msg.Signatures[i] = *sig
	}

	return msg, nil
}

// SignMultiDetached is SignMulti with a detached payload: the
// signatures cover payload and the returned message's Payload is nil.
// Verify it with VerifyMultiDetached.
func SignMultiDetached(payload []byte, signers []*Signer, opts ...SignerOption) (*Sign, error) {
	if payload == nil {
		payload = []byte{}
	}
	msg, err := SignMulti(payload, signers, opts...)
	if err != nil {
		return nil, err
	}
	msg.Payload = nil
	return msg, nil
}

// VerifyMultiDetached is VerifyMulti for a message whose payload is
// detached: payload is the content the signatures cover, and
// msg.Payload is ignored.
func VerifyMultiDetached(msg *Sign, payload []byte, verifiers []*Verifier, policy ...VerifyPolicy) ([]int, error) {
	if payload == nil {
		payload = []byte{}
	}
	m := *msg
	m.Payload = payload
	return VerifyMulti(&m, verifiers, policy...)
}

// VerifyPolicy says which signatures of a COSE_Sign must verify.
type VerifyPolicy int

const (
	// RequireAny accepts the message when at least one signature
	// verifies. It is the default.
	RequireAny VerifyPolicy = iota
	// RequireAll accepts the message only when every signature verifies.
	RequireAll
)

// VerifyMulti verifies the signatures of a COSE_Sign message against
// verifiers and returns the indices of the signatures that verified.
// It returns ErrVerification when the policy (RequireAny unless one is
// given) is not satisfied, including when no signature verifies. A nil
// msg.Payload means the payload is detached; set it before calling, or
// VerifyMulti returns ErrMissingPayload.
//
// Every verifier is tried on every signature until one verifies, so the
// work is up to len(msg.Signatures) × len(verifiers) signature checks.
// UnmarshalSign caps the signatures at DecodeLimits.MaxSignatures (32
// by default).
func VerifyMulti(msg *Sign, verifiers []*Verifier, policy ...VerifyPolicy) ([]int, error) {
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("%w: at least one verifier required", ErrInvalidKey)
	}
	if len(policy) > 1 {
		return nil, fmt.Errorf("%w: at most one VerifyPolicy", ErrInvalidKey)
	}
	p := RequireAny
	if len(policy) == 1 {
		p = policy[0]
	}
	if p != RequireAny && p != RequireAll {
		return nil, fmt.Errorf("%w: unknown VerifyPolicy %d", ErrInvalidKey, p)
	}
	if msg.Payload == nil {
		return nil, ErrMissingPayload
	}

	bodyProtectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	// A verifier whose policy rejects the body's headers (crit) or a
	// signature's headers (crit, alg) verifies nothing there; the last
	// such error is reported if the policy ends up unsatisfied.
	var policyErr error
	var verified []int
	for i, sig := range msg.Signatures {
		for _, v := range verifiers {
			if err := checkCrit(&msg.Protected, &msg.Unprotected, &v.policy); err != nil {
				policyErr = err
				continue
			}
			alg, err := v.checkLayer(&sig.Protected, &sig.Unprotected)
			if err != nil {
				policyErr = err
				continue
			}
			sigProtectedBytes, err := sig.Protected.authProtected(&v.policy)
			if err != nil {
				continue
			}
			body := bodyProtectedBytes
			if v.policy.emptyAsReceived {
				if body, err = msg.Protected.authProtected(&v.policy); err != nil {
					continue
				}
			}
			toBeSigned, err := encodeMultiSigStructure(v.enc, body, sigProtectedBytes, v.external, msg.Payload)
			if err != nil {
				continue
			}
			if v.verifyBytes(alg, toBeSigned, sig.Signature) == nil {
				verified = append(verified, i)
				break
			}
		}
	}

	switch {
	case len(verified) == 0 && policyErr != nil:
		return verified, fmt.Errorf("%w: no signature verified: %w", ErrVerification, policyErr)
	case len(verified) == 0:
		return verified, fmt.Errorf("%w: no signature verified", ErrVerification)
	case p == RequireAll && len(verified) != len(msg.Signatures) && policyErr != nil:
		return verified, fmt.Errorf("%w: %d of %d signatures verified: %w", ErrVerification, len(verified), len(msg.Signatures), policyErr)
	case p == RequireAll && len(verified) != len(msg.Signatures):
		return verified, fmt.Errorf("%w: %d of %d signatures verified", ErrVerification, len(verified), len(msg.Signatures))
	}
	return verified, nil
}

func (s *Sign) AddSignature(signer *Signer) error {
	bodyProtectedBytes, err := s.Protected.encodeProtected()
	if err != nil {
		return err
	}

	sig, err := computeSignature(signer, bodyProtectedBytes, s.Payload, nil)
	if err != nil {
		return err
	}

	s.Signatures = append(s.Signatures, *sig)
	return nil
}

// computeSignature signs one COSE_Signature with the signer's headers.
// external overrides the signer's own external AAD when non-nil.
func computeSignature(signer *Signer, bodyProtectedBytes, payload, external []byte) (*Signature, error) {
	if external == nil {
		external = signer.external
	}
	sig := &Signature{
		Protected:   Headers{params: signer.protected, raw: signer.protectedBytes},
		Unprotected: Headers{params: signer.unprotected},
	}

	toBeSigned, err := encodeMultiSigStructure(signer.enc, bodyProtectedBytes, signer.protectedBytes, external, payload)
	if err != nil {
		return nil, err
	}

	raw, err := signer.signBytes(context.Background(), signer.alg, toBeSigned)
	if err != nil {
		return nil, err
	}
	sig.Signature = raw
	return sig, nil
}

// Sig_structure for COSE_Sign (RFC 9052 §4.4):
// ["Signature", body_protected, sign_protected, external_aad, payload]
func encodeMultiSigStructure(enc *corecbor.Encoder, bodyProtected, signProtected, external, payload []byte) ([]byte, error) {
	if bodyProtected == nil {
		bodyProtected = []byte{}
	}
	if signProtected == nil {
		signProtected = []byte{}
	}
	if external == nil {
		external = []byte{}
	}
	if payload == nil {
		payload = []byte{}
	}
	var elems [5]corecbor.Value
	elems[0] = corecbor.Text("Signature")
	elems[1] = corecbor.Bytes(bodyProtected)
	elems[2] = corecbor.Bytes(signProtected)
	elems[3] = corecbor.Bytes(external)
	elems[4] = corecbor.Bytes(payload)
	return enc.Encode(nil, corecbor.MakeArrayFromSlice(elems[:]))
}
