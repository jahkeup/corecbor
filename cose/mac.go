// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"

	"github.com/jahkeup/corecbor"
)

type MACOption func(*macOpts)

type macOpts struct {
	externalAAD []byte
}

func WithMACExternalAAD(aad []byte) MACOption {
	return func(o *macOpts) { o.externalAAD = aad }
}

func ComputeMAC0(payload, key []byte, alg Algorithm, opts ...MACOption) (*Mac0, error) {
	var o macOpts
	for _, opt := range opts {
		opt(&o)
	}

	hashFunc, err := hmacHashFunc(alg)
	if err != nil {
		return nil, err
	}

	msg := &Mac0{Payload: payload}
	msg.Protected.SetAlgorithm(alg)

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}

	toMAC, err := buildMACStructure(protectedBytes, o.externalAAD, payload)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hashFunc, key)
	mac.Write(toMAC)
	tag := mac.Sum(nil)

	if alg == AlgHMAC256_64 {
		tag = tag[:8]
	}

	msg.Tag = tag
	return msg, nil
}

func VerifyMAC0(msg *Mac0, key []byte, alg Algorithm, opts ...MACOption) error {
	var o macOpts
	for _, opt := range opts {
		opt(&o)
	}

	hashFunc, err := hmacHashFunc(alg)
	if err != nil {
		return err
	}

	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return err
	}

	toMAC, err := buildMACStructure(protectedBytes, o.externalAAD, msg.Payload)
	if err != nil {
		return err
	}

	mac := hmac.New(hashFunc, key)
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

// MAC_structure = ["MAC0", protectedBstr, externalAAD, payload]  (RFC 9052 §6.3)
func buildMACStructure(protectedBytes, externalAAD, payload []byte) ([]byte, error) {
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}
	if externalAAD == nil {
		externalAAD = []byte{}
	}
	if payload == nil {
		payload = []byte{}
	}
	arr := corecbor.Array{
		corecbor.Text("MAC0"),
		corecbor.Bytes(protectedBytes),
		corecbor.Bytes(externalAAD),
		corecbor.Bytes(payload),
	}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, arr)
}

func hmacHashFunc(alg Algorithm) (func() hash.Hash, error) {
	switch alg {
	case AlgHMAC256_64, AlgHMAC256:
		return sha256.New, nil
	case AlgHMAC384:
		return sha512.New384, nil
	case AlgHMAC512:
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: %s is not an HMAC algorithm", ErrUnsupportedAlgorithm, alg)
	}
}
