// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"fmt"

	"github.com/jahkeup/corecbor"
)

// COSE message tags (RFC 9052 §2), from the shared corecbor constants.
const (
	tagSign1    = corecbor.TagCOSESign1
	tagEncrypt0 = corecbor.TagCOSEEncrypt0
	tagMac0     = corecbor.TagCOSEMac0
	tagEncrypt  = corecbor.TagCOSEEncrypt
	tagSign     = corecbor.TagCOSESign
	tagMac      = corecbor.TagCOSEMac
)

var sharedEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic)

// DecodeLimits bounds the work of decoding a message. The Unmarshal*
// functions use the zero value, and a zero field means its default:
// together they are RecommendedDecodeLimits, a bound suited to
// untrusted input. A negative field removes that bound;
// InsecureUnboundedDecodeLimits removes them all.
//
// v0.2 decoded with no budget, nesting depth 256 and any number of
// signatures and recipients (proposal 037 S8).
type DecodeLimits struct {
	// MemoryBudget caps decode allocations in bytes; 0 means 1 MiB, and
	// a negative value means no budget.
	MemoryBudget int
	// MaxDepth caps nesting depth; 0 means 16, and a negative value
	// means the core decoder's limit (256).
	MaxDepth int
	// MaxSignatures caps the signatures in a COSE_Sign; 0 means 32,
	// and a negative value means no cap. VerifyMulti tries every
	// verifier on every signature, so this bounds its work.
	MaxSignatures int
	// MaxRecipients caps the recipients of a COSE_Encrypt or COSE_Mac,
	// counting nested recipients; 0 means 64, and a negative value
	// means no cap.
	MaxRecipients int
	// AllowUnprotectedTyp accepts a typ header (16) in an unprotected
	// bucket, which RFC 9596 §2 forbids (it isn't integrity protected
	// there), for messages from senders that put it there. The header
	// is still returned unprotected; don't rely on it.
	AllowUnprotectedTyp bool
	// AllowDuplicateLabels restores v0.2.2 behavior: a label repeated in
	// a bucket resolves last-wins, and a label may appear in both the
	// protected and unprotected buckets.
	//
	// Deprecated: duplicate labels are invalid (RFC 9052 §3, proposal
	// 027 H4). Retained for migration only; removed no earlier than
	// v0.32.0.
	AllowDuplicateLabels bool
}

// RecommendedDecodeLimits is the recommended bound for untrusted input
// and the default: a 1 MiB decode budget, nesting depth 16, at most 32
// signatures and 64 recipients. Raise MemoryBudget for larger payloads.
var RecommendedDecodeLimits = DecodeLimits{MemoryBudget: 1 << 20, MaxDepth: 16}

// InsecureUnboundedDecodeLimits removes the decode budget and the
// signature and recipient caps, and leaves only the core decoder's
// nesting limit (256), as v0.2 decoded. Use it only for trusted input:
// an attacker can make decoding allocate without bound and VerifyMulti
// do work proportional to the number of signatures.
var InsecureUnboundedDecodeLimits = DecodeLimits{MemoryBudget: -1, MaxDepth: -1, MaxSignatures: -1, MaxRecipients: -1}

const (
	defaultMemoryBudget  = 1 << 20
	defaultMaxDepth      = 16
	defaultMaxSignatures = 32
	defaultMaxRecipients = 64
)

// limit resolves one DecodeLimits field: 0 is def, negative is no limit
// (returned as -1).
func limit(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return -1
	default:
		return v
	}
}

// checkCount enforces a signature or recipient cap.
func checkCount(what string, n, v, def int) error {
	if m := limit(v, def); m >= 0 && n > m {
		return fmt.Errorf("%w: %w: %d %s, at most %d (see DecodeLimits)", ErrMalformed, ErrLimitExceeded, n, what, m)
	}
	return nil
}

// MarshalSign1 encodes a Sign1 message as CBOR with tag 18.
func MarshalSign1(msg *Sign1) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap, err := msg.Unprotected.toCBORMap()
	if err != nil {
		return nil, err
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null()
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	arr := corecbor.MakeArray(
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.Bytes(msg.Signature),
	)

	tagged := corecbor.MakeTag(tagSign1, arr)
	enc := sharedEncoder
	buf := make([]byte, 0, len(protectedBytes)+len(msg.Payload)+len(msg.Signature)+64)
	return enc.Encode(buf, tagged)
}

// UnmarshalSign1 decodes a Sign1 message from CBOR (tagged or untagged).
// It and the other Unmarshal* functions decode under the default
// DecodeLimits (RecommendedDecodeLimits); use the Unmarshal*With
// functions to change them.
func UnmarshalSign1(data []byte) (*Sign1, error) {
	return UnmarshalSign1With(data, DecodeLimits{})
}

// UnmarshalSign1With is UnmarshalSign1 with explicit decode limits; use
// RecommendedDecodeLimits for untrusted input.
func UnmarshalSign1With(data []byte, lim DecodeLimits) (*Sign1, error) {
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}

	var arr []corecbor.Value
	switch v.Kind {
	case corecbor.KindTag:
		if v.TagID() != tagSign1 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind == corecbor.KindArray
		if !ok {
			return nil, fmt.Errorf("%w: tag 18 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.KindArray:
		arr = v.Array()
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Sign1 array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	if arr[0].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, unprot, err := decodeBuckets(protectedBstr, arr[1], lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	if arr[3].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: signature must be bstr", ErrMalformed)
	}
	sig := arr[3].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: signature must be bstr", ErrMalformed)
	}

	return &Sign1{
		Protected:   *prot,
		Unprotected: *unprot,
		Payload:     payload,
		Signature:   sig,
	}, nil
}

func MarshalEncrypt0(msg *Encrypt0) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap, err := msg.Unprotected.toCBORMap()
	if err != nil {
		return nil, err
	}

	var ciphertextVal corecbor.Value
	if msg.Ciphertext == nil {
		ciphertextVal = corecbor.Null()
	} else {
		ciphertextVal = corecbor.Bytes(msg.Ciphertext)
	}

	arr := corecbor.MakeArray(
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		ciphertextVal,
	)

	tagged := corecbor.MakeTag(tagEncrypt0, arr)
	enc := sharedEncoder
	return enc.Encode(nil, tagged)
}

func UnmarshalEncrypt0(data []byte) (*Encrypt0, error) {
	return UnmarshalEncrypt0With(data, DecodeLimits{})
}

// UnmarshalEncrypt0With is UnmarshalEncrypt0 with explicit decode limits; use
// RecommendedDecodeLimits for untrusted input.
func UnmarshalEncrypt0With(data []byte, lim DecodeLimits) (*Encrypt0, error) {
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}

	var arr []corecbor.Value
	switch v.Kind {
	case corecbor.KindTag:
		if v.TagID() != tagEncrypt0 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind == corecbor.KindArray
		if !ok {
			return nil, fmt.Errorf("%w: tag 16 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.KindArray:
		arr = v.Array()
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 3 {
		return nil, fmt.Errorf("%w: Encrypt0 array must have 3 elements, got %d", ErrMalformed, len(arr))
	}

	if arr[0].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, unprot, err := decodeBuckets(protectedBstr, arr[1], lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var ciphertext []byte
	switch arr[2].Kind {
	case corecbor.KindBytes:
		ciphertext = arr[2].BytesVal()
	case corecbor.KindNull:
		ciphertext = nil
	default:
		return nil, fmt.Errorf("%w: ciphertext must be bstr or null", ErrMalformed)
	}

	return &Encrypt0{
		Protected:   *prot,
		Unprotected: *unprot,
		Ciphertext:  ciphertext,
	}, nil
}

func MarshalMac0(msg *Mac0) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap, err := msg.Unprotected.toCBORMap()
	if err != nil {
		return nil, err
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null()
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	arr := corecbor.MakeArray(
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.Bytes(msg.Tag),
	)

	tagged := corecbor.MakeTag(tagMac0, arr)
	enc := sharedEncoder
	return enc.Encode(nil, tagged)
}

func UnmarshalMac0(data []byte) (*Mac0, error) {
	return UnmarshalMac0With(data, DecodeLimits{})
}

// UnmarshalMac0With is UnmarshalMac0 with explicit decode limits; use
// RecommendedDecodeLimits for untrusted input.
func UnmarshalMac0With(data []byte, lim DecodeLimits) (*Mac0, error) {
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}

	var arr []corecbor.Value
	switch v.Kind {
	case corecbor.KindTag:
		if v.TagID() != tagMac0 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind == corecbor.KindArray
		if !ok {
			return nil, fmt.Errorf("%w: tag 17 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.KindArray:
		arr = v.Array()
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Mac0 array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	if arr[0].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, unprot, err := decodeBuckets(protectedBstr, arr[1], lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	tag := arr[3].BytesVal()
	ok := arr[3].Kind == corecbor.KindBytes
	if !ok {
		return nil, fmt.Errorf("%w: tag must be bstr", ErrMalformed)
	}

	return &Mac0{
		Protected:   *prot,
		Unprotected: *unprot,
		Payload:     payload,
		Tag:         []byte(tag),
	}, nil
}

func MarshalEncrypt(msg *Encrypt) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap, err := msg.Unprotected.toCBORMap()
	if err != nil {
		return nil, err
	}

	var ciphertextVal corecbor.Value
	if msg.Ciphertext == nil {
		ciphertextVal = corecbor.Null()
	} else {
		ciphertextVal = corecbor.Bytes(msg.Ciphertext)
	}

	recipientsArr, err := encodeRecipients(msg.Recipients)
	if err != nil {
		return nil, err
	}

	arr := corecbor.MakeArray(
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		ciphertextVal,
		corecbor.MakeArrayFromSlice(recipientsArr),
	)

	tagged := corecbor.MakeTag(tagEncrypt, arr)
	enc := sharedEncoder
	return enc.Encode(nil, tagged)
}

func UnmarshalEncrypt(data []byte) (*Encrypt, error) {
	return UnmarshalEncryptWith(data, DecodeLimits{})
}

// UnmarshalEncryptWith is UnmarshalEncrypt with explicit decode limits; use
// RecommendedDecodeLimits for untrusted input.
func UnmarshalEncryptWith(data []byte, lim DecodeLimits) (*Encrypt, error) {
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}

	var arr []corecbor.Value
	switch v.Kind {
	case corecbor.KindTag:
		if v.TagID() != tagEncrypt {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind == corecbor.KindArray
		if !ok {
			return nil, fmt.Errorf("%w: tag 96 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.KindArray:
		arr = v.Array()
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Encrypt array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	if arr[0].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, unprot, err := decodeBuckets(protectedBstr, arr[1], lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var ciphertext []byte
	switch arr[2].Kind {
	case corecbor.KindBytes:
		ciphertext = arr[2].BytesVal()
	case corecbor.KindNull:
		ciphertext = nil
	default:
		return nil, fmt.Errorf("%w: ciphertext must be bstr or null", ErrMalformed)
	}

	recipientsArr := arr[3].Array()
	ok := arr[3].Kind == corecbor.KindArray
	if !ok {
		return nil, fmt.Errorf("%w: recipients must be array", ErrMalformed)
	}

	var count int
	recipients, err := decodeRecipients(recipientsArr, lim, &count, "recipient ")
	if err != nil {
		return nil, err
	}

	return &Encrypt{
		Protected:   *prot,
		Unprotected: *unprot,
		Ciphertext:  ciphertext,
		Recipients:  recipients,
	}, nil
}

func MarshalSign(msg *Sign) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap, err := msg.Unprotected.toCBORMap()
	if err != nil {
		return nil, err
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null()
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	signaturesArr := make([]corecbor.Value, len(msg.Signatures))
	for i, s := range msg.Signatures {
		sProtBytes, err := s.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if sProtBytes == nil {
			sProtBytes = []byte{}
		}
		sUnprotMap, err := s.Unprotected.toCBORMap()
		if err != nil {
			return nil, err
		}
		if sUnprotMap.IsZero() {
			sUnprotMap = corecbor.MakeMap()
		}
		signaturesArr[i] = corecbor.MakeArray(
			corecbor.Bytes(sProtBytes),
			sUnprotMap,
			corecbor.Bytes(s.Signature),
		)
	}

	arr := corecbor.MakeArray(
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.MakeArrayFromSlice(signaturesArr),
	)

	tagged := corecbor.MakeTag(tagSign, arr)
	enc := sharedEncoder
	return enc.Encode(nil, tagged)
}

func UnmarshalSign(data []byte) (*Sign, error) {
	return UnmarshalSignWith(data, DecodeLimits{})
}

// UnmarshalSignWith is UnmarshalSign with explicit decode limits; use
// RecommendedDecodeLimits for untrusted input.
func UnmarshalSignWith(data []byte, lim DecodeLimits) (*Sign, error) {
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}

	var arr []corecbor.Value
	switch v.Kind {
	case corecbor.KindTag:
		if v.TagID() != tagSign {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind == corecbor.KindArray
		if !ok {
			return nil, fmt.Errorf("%w: tag 98 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.KindArray:
		arr = v.Array()
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Sign array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	if arr[0].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, unprot, err := decodeBuckets(protectedBstr, arr[1], lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	sigsArr := arr[3].Array()
	ok := arr[3].Kind == corecbor.KindArray
	if !ok {
		return nil, fmt.Errorf("%w: signatures must be array", ErrMalformed)
	}

	if err := checkCount("signatures", len(sigsArr), lim.MaxSignatures, defaultMaxSignatures); err != nil {
		return nil, err
	}
	signatures := make([]Signature, len(sigsArr))
	for i, sv := range sigsArr {
		sArr := sv.Array()
		ok := sv.Kind == corecbor.KindArray
		if !ok || len(sArr) != 3 {
			return nil, fmt.Errorf("%w: signature %d must be 3-element array", ErrMalformed, i)
		}

		sProtBstr := sArr[0].BytesVal()
		ok = sArr[0].Kind == corecbor.KindBytes
		if !ok {
			return nil, fmt.Errorf("%w: signature %d protected must be bstr", ErrMalformed, i)
		}
		sProt, sUnprot, err := decodeBuckets([]byte(sProtBstr), sArr[1], lim)
		if err != nil {
			return nil, fmt.Errorf("%w: signature %d: %w", ErrMalformed, i, err)
		}

		sigBytes := sArr[2].BytesVal()
		ok = sArr[2].Kind == corecbor.KindBytes
		if !ok {
			return nil, fmt.Errorf("%w: signature %d value must be bstr", ErrMalformed, i)
		}

		signatures[i] = Signature{
			Protected:   *sProt,
			Unprotected: *sUnprot,
			Signature:   []byte(sigBytes),
		}
	}

	return &Sign{
		Protected:   *prot,
		Unprotected: *unprot,
		Payload:     payload,
		Signatures:  signatures,
	}, nil
}

func MarshalMac(msg *Mac) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap, err := msg.Unprotected.toCBORMap()
	if err != nil {
		return nil, err
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null()
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	recipientsArr, err := encodeRecipients(msg.Recipients)
	if err != nil {
		return nil, err
	}

	arr := corecbor.MakeArray(
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.Bytes(msg.Tag),
		corecbor.MakeArrayFromSlice(recipientsArr),
	)

	tagged := corecbor.MakeTag(tagMac, arr)
	enc := sharedEncoder
	return enc.Encode(nil, tagged)
}

func UnmarshalMac(data []byte) (*Mac, error) {
	return UnmarshalMacWith(data, DecodeLimits{})
}

// UnmarshalMacWith is UnmarshalMac with explicit decode limits; use
// RecommendedDecodeLimits for untrusted input.
func UnmarshalMacWith(data []byte, lim DecodeLimits) (*Mac, error) {
	v, err := newMessageDecoder(lim).Decode(data)
	if err != nil {
		return nil, decodeError(err)
	}

	var arr []corecbor.Value
	switch v.Kind {
	case corecbor.KindTag:
		if v.TagID() != tagMac {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind == corecbor.KindArray
		if !ok {
			return nil, fmt.Errorf("%w: tag 97 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.KindArray:
		arr = v.Array()
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 5 {
		return nil, fmt.Errorf("%w: Mac array must have 5 elements, got %d", ErrMalformed, len(arr))
	}

	if arr[0].Kind != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, unprot, err := decodeBuckets(protectedBstr, arr[1], lim)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	tag := arr[3].BytesVal()
	ok := arr[3].Kind == corecbor.KindBytes
	if !ok {
		return nil, fmt.Errorf("%w: tag must be bstr", ErrMalformed)
	}

	recipientsArr := arr[4].Array()
	ok = arr[4].Kind == corecbor.KindArray
	if !ok {
		return nil, fmt.Errorf("%w: recipients must be array", ErrMalformed)
	}

	var count int
	recipients, err := decodeRecipients(recipientsArr, lim, &count, "recipient ")
	if err != nil {
		return nil, err
	}

	return &Mac{
		Protected:   *prot,
		Unprotected: *unprot,
		Payload:     payload,
		Tag:         []byte(tag),
		Recipients:  recipients,
	}, nil
}

// encodeRecipients encodes COSE_recipient structures, with a fourth
// element for nested recipients when there are any (RFC 9052 §5.1).
func encodeRecipients(rs []Recipient) ([]corecbor.Value, error) {
	out := make([]corecbor.Value, len(rs))
	for i, r := range rs {
		rProtBytes, err := r.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if rProtBytes == nil {
			rProtBytes = []byte{}
		}
		rUnprotMap, err := r.Unprotected.toCBORMap()
		if err != nil {
			return nil, err
		}
		if rUnprotMap.IsZero() {
			rUnprotMap = corecbor.MakeMap()
		}
		var rCipherVal corecbor.Value
		if r.Ciphertext == nil {
			rCipherVal = corecbor.Bytes(nil)
		} else {
			rCipherVal = corecbor.Bytes(r.Ciphertext)
		}
		elems := []corecbor.Value{corecbor.Bytes(rProtBytes), rUnprotMap, rCipherVal}
		if len(r.Recipients) > 0 {
			nested, err := encodeRecipients(r.Recipients)
			if err != nil {
				return nil, err
			}
			elems = append(elems, corecbor.MakeArrayFromSlice(nested))
		}
		out[i] = corecbor.MakeArrayFromSlice(elems)
	}
	return out, nil
}

// decodeRecipients decodes a recipients array. A COSE_recipient has
// three elements, or four with nested recipients (RFC 9052 §5.1);
// nested ones count toward lim.MaxRecipients through count, and their
// depth is bounded by lim.MaxDepth in the decoder. path prefixes error
// messages ("recipient 0.1").
func decodeRecipients(arr []corecbor.Value, lim DecodeLimits, count *int, path string) ([]Recipient, error) {
	*count += len(arr)
	if err := checkCount("recipients", *count, lim.MaxRecipients, defaultMaxRecipients); err != nil {
		return nil, err
	}
	recipients := make([]Recipient, len(arr))
	for i, rv := range arr {
		rArr := rv.Array()
		if rv.Kind != corecbor.KindArray || (len(rArr) != 3 && len(rArr) != 4) {
			return nil, fmt.Errorf("%w: %s%d must be a 3- or 4-element array", ErrMalformed, path, i)
		}
		if rArr[0].Kind != corecbor.KindBytes {
			return nil, fmt.Errorf("%w: %s%d protected must be bstr", ErrMalformed, path, i)
		}
		rProt, rUnprot, err := decodeBuckets(rArr[0].BytesVal(), rArr[1], lim)
		if err != nil {
			return nil, fmt.Errorf("%w: %s%d: %w", ErrMalformed, path, i, err)
		}

		var rCiphertext []byte
		switch rArr[2].Kind {
		case corecbor.KindBytes:
			rCiphertext = rArr[2].BytesVal()
		case corecbor.KindNull:
			rCiphertext = nil
		default:
			return nil, fmt.Errorf("%w: %s%d ciphertext must be bstr or null", ErrMalformed, path, i)
		}

		r := Recipient{Protected: *rProt, Unprotected: *rUnprot, Ciphertext: rCiphertext}
		if len(rArr) == 4 {
			// "If there are no recipient information structures, this
			// element is absent" (§5.1): present means [+COSE_recipient].
			if rArr[3].Kind != corecbor.KindArray || len(rArr[3].Array()) == 0 {
				return nil, fmt.Errorf("%w: %s%d nested recipients must be a non-empty array", ErrMalformed, path, i)
			}
			r.Recipients, err = decodeRecipients(rArr[3].Array(), lim, count, fmt.Sprintf("%s%d.", path, i))
			if err != nil {
				return nil, err
			}
		}
		recipients[i] = r
	}
	return recipients, nil
}
