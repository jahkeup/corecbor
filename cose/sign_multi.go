// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"fmt"

	"github.com/jahkeup/corecbor"
)

func SignMulti(payload []byte, signers []*Signer, opts ...SignerOption) (*Sign, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("%w: at least one signer required", ErrInvalidKey)
	}

	msg := &Sign{
		Payload:    payload,
		Signatures: make([]Signature, len(signers)),
	}

	bodyProtectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	for i, signer := range signers {
		sig, err := computeSignature(signer, bodyProtectedBytes, payload)
		if err != nil {
			return nil, fmt.Errorf("signer %d: %w", i, err)
		}
		msg.Signatures[i] = *sig
	}

	return msg, nil
}

func VerifyMulti(msg *Sign, verifiers []*Verifier) ([]int, error) {
	if len(verifiers) == 0 {
		return nil, fmt.Errorf("%w: at least one verifier required", ErrInvalidKey)
	}

	bodyProtectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	var verified []int
	for i, sig := range msg.Signatures {
		for _, v := range verifiers {
			sigProtectedBytes, err := sig.Protected.encodeProtected()
			if err != nil {
				continue
			}
			toBeSigned, err := encodeMultiSigStructure(v.enc, bodyProtectedBytes, sigProtectedBytes, v.external, msg.Payload)
			if err != nil {
				continue
			}
			if v.verifyBytes(toBeSigned, sig.Signature) == nil {
				verified = append(verified, i)
				break
			}
		}
	}

	return verified, nil
}

func (s *Sign) AddSignature(signer *Signer) error {
	bodyProtectedBytes, err := s.Protected.encodeProtected()
	if err != nil {
		return err
	}

	sig, err := computeSignature(signer, bodyProtectedBytes, s.Payload)
	if err != nil {
		return err
	}

	s.Signatures = append(s.Signatures, *sig)
	return nil
}

func computeSignature(signer *Signer, bodyProtectedBytes, payload []byte) (*Signature, error) {
	sig := &Signature{}
	sig.Protected.SetAlgorithm(signer.alg)

	sigProtectedBytes, err := sig.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	toBeSigned, err := encodeMultiSigStructure(signer.enc, bodyProtectedBytes, sigProtectedBytes, signer.external, payload)
	if err != nil {
		return nil, err
	}

	raw, err := signer.signBytes(toBeSigned)
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
	return enc.Encode(nil, corecbor.MakeArray(elems[:]...))
}
