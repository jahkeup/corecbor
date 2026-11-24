// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/jahkeup/corecbor"
)

// ComputeMACMulti computes a COSE_Mac over payload for recipients.
// key is the MAC key to distribute; with a nil key a random one is
// generated. A single direct recipient supplies the MAC key instead: a
// DirectKey (alg direct, RFC 9052 §8.5.1), with key nil or equal to it,
// or direct key agreement (§8.5.4), with key nil. A direct recipient
// alongside others is ErrInvalidKey.
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

	dcek, dr, directEnc, err := directEncryption(recipients, alg, cekLen)
	if err != nil {
		return nil, err
	}
	ka, direct, err := directAgreement(recipients, o.legacy)
	if err != nil {
		return nil, err
	}
	msg := &Mac{Payload: payload}
	var cek []byte
	switch {
	case directEnc:
		// RFC 9052 §8.5.1: the shared key is the MAC key. A key passed
		// as well must be that key.
		if key != nil && !bytes.Equal(key, dcek) {
			return nil, fmt.Errorf("%w: a direct recipient's key is the MAC key; pass it or a nil key", ErrInvalidKey)
		}
		if err := o.checkMACKey(dcek, alg); err != nil {
			return nil, err
		}
		cek = dcek
		msg.Recipients = []Recipient{dr}
		direct = true
	case direct:
		// RFC 9052 §8.5.4: the agreed key is the MAC key.
		if key != nil {
			return nil, fmt.Errorf("%w: a direct key agreement recipient derives the MAC key; pass a nil key", ErrInvalidKey)
		}
		var r Recipient
		cek, r, err = agreeRecipient(ka, alg, cekLen)
		if err != nil {
			return nil, err
		}
		msg.Recipients = []Recipient{r}
	case key != nil:
		if err := o.checkMACKey(key, alg); err != nil {
			return nil, err
		}
		cek = key
	default:
		cek = make([]byte, cekLen)
		if _, err := rand.Read(cek); err != nil {
			return nil, fmt.Errorf("generating MAC key: %w", err)
		}
	}

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

	if !direct {
		msg.Recipients, err = sealRecipients(cek, alg, recipients, o.legacy)
		if err != nil {
			return nil, err
		}
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
	cek, err := openRecipient(&r, recipient, alg, cekLen, &encryptOpts{policy: o.policy, legacy: o.legacy, allowProtRecipient: o.allowProtRecipient})
	if err != nil {
		if errors.Is(err, ErrAlgorithmMismatch) || errors.Is(err, ErrCriticalHeader) || errors.Is(err, ErrMalformed) {
			return err
		}
		if errors.Is(err, ErrUnsupportedAlgorithm) {
			// A v0.2 recipient encoding: say which selector reads it.
			return fmt.Errorf("%w: %w", ErrMACVerification, err)
		}
		return fmt.Errorf("%w: key unwrap failed", ErrMACVerification)
	}
	if err := o.checkMACKey(cek, alg); err != nil {
		return fmt.Errorf("%w: %w", ErrMACVerification, err)
	}

	protectedBytes, err := msg.Protected.authProtected(&o.policy)
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
