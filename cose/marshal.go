// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"fmt"

	"github.com/jahkeup/corecbor"
)

const (
	tagSign1    uint64 = 18
	tagEncrypt0 uint64 = 16
	tagMac0     uint64 = 17
	tagEncrypt  uint64 = 96
	tagSign     uint64 = 98
	tagMac      uint64 = 97
)

var sharedEncoder = corecbor.NewShared(corecbor.ModeCoreDeterministic)

// MarshalSign1 encodes a Sign1 message as CBOR with tag 18.
func MarshalSign1(msg *Sign1) ([]byte, error) {
	protectedBytes, err := msg.Protected.encodeProtected()
	if err != nil {
		return nil, err
	}
	if protectedBytes == nil {
		protectedBytes = []byte{}
	}

	unprotectedMap := msg.Unprotected.toCBORMap()

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
func UnmarshalSign1(data []byte) (*Sign1, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr []corecbor.Value
	switch v.Kind() {
	case corecbor.KindTag:
		if v.TagID() != tagSign1 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind() == corecbor.KindArray
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

	if arr[0].Kind() != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected(protectedBstr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind() {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	if arr[3].Kind() != corecbor.KindBytes {
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

	unprotectedMap := msg.Unprotected.toCBORMap()

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
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr []corecbor.Value
	switch v.Kind() {
	case corecbor.KindTag:
		if v.TagID() != tagEncrypt0 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind() == corecbor.KindArray
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

	if arr[0].Kind() != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected(protectedBstr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var ciphertext []byte
	switch arr[2].Kind() {
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

	unprotectedMap := msg.Unprotected.toCBORMap()

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
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr []corecbor.Value
	switch v.Kind() {
	case corecbor.KindTag:
		if v.TagID() != tagMac0 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind() == corecbor.KindArray
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

	if arr[0].Kind() != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected(protectedBstr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind() {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	tag := arr[3].BytesVal()
	ok := arr[3].Kind() == corecbor.KindBytes
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

	unprotectedMap := msg.Unprotected.toCBORMap()

	var ciphertextVal corecbor.Value
	if msg.Ciphertext == nil {
		ciphertextVal = corecbor.Null()
	} else {
		ciphertextVal = corecbor.Bytes(msg.Ciphertext)
	}

	recipientsArr := make([]corecbor.Value, len(msg.Recipients))
	for i, r := range msg.Recipients {
		rProtBytes, err := r.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if rProtBytes == nil {
			rProtBytes = []byte{}
		}
		rUnprotMap := r.Unprotected.toCBORMap()
		if rUnprotMap.IsZero() {
			rUnprotMap = corecbor.MakeMap()
		}
		var rCipherVal corecbor.Value
		if r.Ciphertext == nil {
			rCipherVal = corecbor.Bytes(nil)
		} else {
			rCipherVal = corecbor.Bytes(r.Ciphertext)
		}
		recipientsArr[i] = corecbor.MakeArray(
			corecbor.Bytes(rProtBytes),
			rUnprotMap,
			rCipherVal,
		)
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
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr []corecbor.Value
	switch v.Kind() {
	case corecbor.KindTag:
		if v.TagID() != tagEncrypt {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind() == corecbor.KindArray
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

	if arr[0].Kind() != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected(protectedBstr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var ciphertext []byte
	switch arr[2].Kind() {
	case corecbor.KindBytes:
		ciphertext = arr[2].BytesVal()
	case corecbor.KindNull:
		ciphertext = nil
	default:
		return nil, fmt.Errorf("%w: ciphertext must be bstr or null", ErrMalformed)
	}

	recipientsArr := arr[3].Array()
	ok := arr[3].Kind() == corecbor.KindArray
	if !ok {
		return nil, fmt.Errorf("%w: recipients must be array", ErrMalformed)
	}

	recipients := make([]Recipient, len(recipientsArr))
	for i, rv := range recipientsArr {
		rArr := rv.Array()
		ok := rv.Kind() == corecbor.KindArray
		if !ok || len(rArr) != 3 {
			return nil, fmt.Errorf("%w: recipient %d must be 3-element array", ErrMalformed, i)
		}

		rProtBstr := rArr[0].BytesVal()
		ok = rArr[0].Kind() == corecbor.KindBytes
		if !ok {
			return nil, fmt.Errorf("%w: recipient %d protected must be bstr", ErrMalformed, i)
		}
		rProt, err := decodeProtected([]byte(rProtBstr))
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrMalformed, i, err)
		}

		rUnprot, err := decodeUnprotected(rArr[1])
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrMalformed, i, err)
		}

		var rCiphertext []byte
		switch rArr[2].Kind() {
		case corecbor.KindBytes:
			rCiphertext = rArr[2].BytesVal()
		case corecbor.KindNull:
			rCiphertext = nil
		default:
			return nil, fmt.Errorf("%w: recipient %d ciphertext must be bstr or null", ErrMalformed, i)
		}

		recipients[i] = Recipient{
			Protected:   *rProt,
			Unprotected: *rUnprot,
			Ciphertext:  rCiphertext,
		}
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

	unprotectedMap := msg.Unprotected.toCBORMap()

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
		sUnprotMap := s.Unprotected.toCBORMap()
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
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr []corecbor.Value
	switch v.Kind() {
	case corecbor.KindTag:
		if v.TagID() != tagSign {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind() == corecbor.KindArray
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

	if arr[0].Kind() != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected(protectedBstr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind() {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	sigsArr := arr[3].Array()
	ok := arr[3].Kind() == corecbor.KindArray
	if !ok {
		return nil, fmt.Errorf("%w: signatures must be array", ErrMalformed)
	}

	signatures := make([]Signature, len(sigsArr))
	for i, sv := range sigsArr {
		sArr := sv.Array()
		ok := sv.Kind() == corecbor.KindArray
		if !ok || len(sArr) != 3 {
			return nil, fmt.Errorf("%w: signature %d must be 3-element array", ErrMalformed, i)
		}

		sProtBstr := sArr[0].BytesVal()
		ok = sArr[0].Kind() == corecbor.KindBytes
		if !ok {
			return nil, fmt.Errorf("%w: signature %d protected must be bstr", ErrMalformed, i)
		}
		sProt, err := decodeProtected([]byte(sProtBstr))
		if err != nil {
			return nil, fmt.Errorf("%w: signature %d: %v", ErrMalformed, i, err)
		}

		sUnprot, err := decodeUnprotected(sArr[1])
		if err != nil {
			return nil, fmt.Errorf("%w: signature %d: %v", ErrMalformed, i, err)
		}

		sigBytes := sArr[2].BytesVal()
		ok = sArr[2].Kind() == corecbor.KindBytes
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

	unprotectedMap := msg.Unprotected.toCBORMap()

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null()
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	recipientsArr := make([]corecbor.Value, len(msg.Recipients))
	for i, r := range msg.Recipients {
		rProtBytes, err := r.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if rProtBytes == nil {
			rProtBytes = []byte{}
		}
		rUnprotMap := r.Unprotected.toCBORMap()
		if rUnprotMap.IsZero() {
			rUnprotMap = corecbor.MakeMap()
		}
		var rCipherVal corecbor.Value
		if r.Ciphertext == nil {
			rCipherVal = corecbor.Bytes(nil)
		} else {
			rCipherVal = corecbor.Bytes(r.Ciphertext)
		}
		recipientsArr[i] = corecbor.MakeArray(
			corecbor.Bytes(rProtBytes),
			rUnprotMap,
			rCipherVal,
		)
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
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr []corecbor.Value
	switch v.Kind() {
	case corecbor.KindTag:
		if v.TagID() != tagMac {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, v.TagID())
		}
		a := v.TagInner().Array()
		ok := v.TagInner().Kind() == corecbor.KindArray
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

	if arr[0].Kind() != corecbor.KindBytes {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}
	protectedBstr := arr[0].BytesVal()
	if false {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected(protectedBstr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch arr[2].Kind() {
	case corecbor.KindBytes:
		payload = arr[2].BytesVal()
	case corecbor.KindNull:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	tag := arr[3].BytesVal()
	ok := arr[3].Kind() == corecbor.KindBytes
	if !ok {
		return nil, fmt.Errorf("%w: tag must be bstr", ErrMalformed)
	}

	recipientsArr := arr[4].Array()
	ok = arr[4].Kind() == corecbor.KindArray
	if !ok {
		return nil, fmt.Errorf("%w: recipients must be array", ErrMalformed)
	}

	recipients := make([]Recipient, len(recipientsArr))
	for i, rv := range recipientsArr {
		rArr := rv.Array()
		ok := rv.Kind() == corecbor.KindArray
		if !ok || len(rArr) != 3 {
			return nil, fmt.Errorf("%w: recipient %d must be 3-element array", ErrMalformed, i)
		}

		rProtBstr := rArr[0].BytesVal()
		ok = rArr[0].Kind() == corecbor.KindBytes
		if !ok {
			return nil, fmt.Errorf("%w: recipient %d protected must be bstr", ErrMalformed, i)
		}
		rProt, err := decodeProtected([]byte(rProtBstr))
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrMalformed, i, err)
		}

		rUnprot, err := decodeUnprotected(rArr[1])
		if err != nil {
			return nil, fmt.Errorf("%w: recipient %d: %v", ErrMalformed, i, err)
		}

		var rCiphertext []byte
		switch rArr[2].Kind() {
		case corecbor.KindBytes:
			rCiphertext = rArr[2].BytesVal()
		case corecbor.KindNull:
			rCiphertext = nil
		default:
			return nil, fmt.Errorf("%w: recipient %d ciphertext must be bstr or null", ErrMalformed, i)
		}

		recipients[i] = Recipient{
			Protected:   *rProt,
			Unprotected: *rUnprot,
			Ciphertext:  rCiphertext,
		}
	}

	return &Mac{
		Protected:   *prot,
		Unprotected: *unprot,
		Payload:     payload,
		Tag:         []byte(tag),
		Recipients:  recipients,
	}, nil
}
