// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/jahkeup/corecbor"
)

func ComputeMACMulti(payload []byte, key []byte, alg Algorithm, recipients []KeyDeriver, opts ...MACOption) (*Mac, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("%w: at least one recipient required", ErrInvalidKey)
	}

	var o macOpts
	for _, opt := range opts {
		opt(&o)
	}

	hashFunc, err := hmacHashFunc(alg)
	if err != nil {
		return nil, err
	}

	cekLen := hmacKeyLen(alg)

	var cek []byte
	if key != nil {
		if err := o.checkMACKey(key, alg); err != nil {
			return nil, err
		}
		cek = key
	} else {
		cek = make([]byte, cekLen)
		if _, err := rand.Read(cek); err != nil {
			return nil, fmt.Errorf("generating MAC key: %w", err)
		}
	}

	msg := &Mac{Payload: payload}
	msg.Protected.SetAlgorithm(alg)

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	toMAC, err := buildMACStructureMulti(protectedBytes, o.externalAAD, payload)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hashFunc, cek)
	mac.Write(toMAC)
	tag := mac.Sum(nil)
	if alg == AlgHMAC256_64 {
		tag = tag[:8]
	}
	msg.Tag = tag

	wrapOpts := KeyWrapOpts{CEKAlgorithm: alg, CEKLength: cekLen}
	msg.Recipients = make([]Recipient, len(recipients))
	for i, r := range recipients {
		ciphertext, headers, err := r.WrapKey(cek, wrapOpts)
		if err != nil {
			return nil, fmt.Errorf("recipient %d: %w", i, err)
		}
		msg.Recipients[i] = Recipient{
			Unprotected: headers,
			Ciphertext:  ciphertext,
		}
		msg.Recipients[i].Protected.SetAlgorithm(r.Algorithm())
	}

	return msg, nil
}

// VerifyMACMulti verifies a COSE_Mac tag using the key recovered by
// recipient. A nil msg.Payload means the payload is detached; set it
// before calling, or VerifyMACMulti returns ErrMissingPayload.
//
// The MAC algorithm comes from the protected header, which the sender
// (or an attacker) chose, so it must be protected and in the allowed
// set: HMAC 256/256, 384/384 or 512/512 unless WithMACAlgorithms says
// otherwise. Header-selected HMAC 256/64 is rejected by default because
// it truncates the tag to 64 bits. WithMACExternalAAD supplies the
// external AAD the sender used.
func VerifyMACMulti(msg *Mac, recipient KeyDeriver, recipientIndex int, opts ...MACOption) error {
	if msg.Payload == nil {
		return ErrMissingPayload
	}
	if recipientIndex < 0 || recipientIndex >= len(msg.Recipients) {
		return fmt.Errorf("%w: recipient index out of range", ErrMACVerification)
	}
	var o macOpts
	for _, opt := range opts {
		opt(&o)
	}

	r := msg.Recipients[recipientIndex]
	if err := checkCrit(&msg.Protected, &msg.Unprotected, &o.policy); err != nil {
		return err
	}
	if err := checkCrit(&r.Protected, &r.Unprotected, &o.policy); err != nil {
		return err
	}
	alg, err := multiAlg(&msg.Protected, &msg.Unprotected, &o.policy, defaultMACMultiAlgs)
	if err != nil {
		return err
	}

	hashFunc, err := hmacHashFunc(alg)
	if err != nil {
		return err
	}

	cekLen := hmacKeyLen(alg)
	unwrapOpts := KeyUnwrapOpts{CEKAlgorithm: alg, CEKLength: cekLen}
	cek, err := recipient.UnwrapKey(r.Ciphertext, r.Unprotected, unwrapOpts)
	if err != nil {
		return fmt.Errorf("%w: key unwrap failed", ErrMACVerification)
	}
	if err := o.checkMACKey(cek, alg); err != nil {
		return fmt.Errorf("%w: %w", ErrMACVerification, err)
	}

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return err
	}

	toMAC, err := buildMACStructureMulti(protectedBytes, o.externalAAD, msg.Payload)
	if err != nil {
		return err
	}

	mac := hmac.New(hashFunc, cek)
	mac.Write(toMAC)
	expected := mac.Sum(nil)
	if alg == AlgHMAC256_64 {
		expected = expected[:8]
	}

	if subtle.ConstantTimeCompare(msg.Tag, expected) != 1 {
		return ErrMACVerification
	}
	return nil
}

// MAC_structure for COSE_Mac (RFC 9052 §6.3): ["MAC", protectedBstr, externalAAD, payload]
func buildMACStructureMulti(protectedBytes, externalAAD, payload []byte) ([]byte, error) {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	if payload == nil {
		payload = []byte{}
	}
	arr := corecbor.MakeArray(
		corecbor.Text("MAC"),
		corecbor.Bytes(protectedBytes),
		corecbor.Bytes(externalAAD),
		corecbor.Bytes(payload),
	)
	enc := sharedEncoder
	return enc.Encode(nil, arr)
}

func hmacKeyLen(alg Algorithm) int {
	switch alg {
	case AlgHMAC256_64, AlgHMAC256:
		return 32
	case AlgHMAC384:
		return 48
	case AlgHMAC512:
		return 64
	default:
		return 32
	}
}
