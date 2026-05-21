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
	if unprotectedMap == nil {
		unprotectedMap = corecbor.Map{}
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null{}
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	arr := corecbor.Array{
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.Bytes(msg.Signature),
	}

	tagged := corecbor.Tag{ID: tagSign1, Inner: arr}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, tagged)
}

// UnmarshalSign1 decodes a Sign1 message from CBOR (tagged or untagged).
func UnmarshalSign1(data []byte) (*Sign1, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr corecbor.Array
	switch x := v.(type) {
	case corecbor.Tag:
		if x.ID != tagSign1 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, x.ID)
		}
		a, ok := x.Inner.(corecbor.Array)
		if !ok {
			return nil, fmt.Errorf("%w: tag 18 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.Array:
		arr = x
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Sign1 array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	protectedBstr, ok := arr[0].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected([]byte(protectedBstr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch p := arr[2].(type) {
	case corecbor.Bytes:
		payload = []byte(p)
	case corecbor.Null:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	sig, ok := arr[3].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: signature must be bstr", ErrMalformed)
	}

	return &Sign1{
		Protected:   *prot,
		Unprotected: *unprot,
		Payload:     payload,
		Signature:   []byte(sig),
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
	if unprotectedMap == nil {
		unprotectedMap = corecbor.Map{}
	}

	var ciphertextVal corecbor.Value
	if msg.Ciphertext == nil {
		ciphertextVal = corecbor.Null{}
	} else {
		ciphertextVal = corecbor.Bytes(msg.Ciphertext)
	}

	arr := corecbor.Array{
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		ciphertextVal,
	}

	tagged := corecbor.Tag{ID: tagEncrypt0, Inner: arr}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, tagged)
}

func UnmarshalEncrypt0(data []byte) (*Encrypt0, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr corecbor.Array
	switch x := v.(type) {
	case corecbor.Tag:
		if x.ID != tagEncrypt0 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, x.ID)
		}
		a, ok := x.Inner.(corecbor.Array)
		if !ok {
			return nil, fmt.Errorf("%w: tag 16 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.Array:
		arr = x
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 3 {
		return nil, fmt.Errorf("%w: Encrypt0 array must have 3 elements, got %d", ErrMalformed, len(arr))
	}

	protectedBstr, ok := arr[0].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected([]byte(protectedBstr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var ciphertext []byte
	switch c := arr[2].(type) {
	case corecbor.Bytes:
		ciphertext = []byte(c)
	case corecbor.Null:
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
	if unprotectedMap == nil {
		unprotectedMap = corecbor.Map{}
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null{}
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	arr := corecbor.Array{
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.Bytes(msg.Tag),
	}

	tagged := corecbor.Tag{ID: tagMac0, Inner: arr}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, tagged)
}

func UnmarshalMac0(data []byte) (*Mac0, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr corecbor.Array
	switch x := v.(type) {
	case corecbor.Tag:
		if x.ID != tagMac0 {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, x.ID)
		}
		a, ok := x.Inner.(corecbor.Array)
		if !ok {
			return nil, fmt.Errorf("%w: tag 17 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.Array:
		arr = x
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Mac0 array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	protectedBstr, ok := arr[0].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected([]byte(protectedBstr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch p := arr[2].(type) {
	case corecbor.Bytes:
		payload = []byte(p)
	case corecbor.Null:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	tag, ok := arr[3].(corecbor.Bytes)
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
	if unprotectedMap == nil {
		unprotectedMap = corecbor.Map{}
	}

	var ciphertextVal corecbor.Value
	if msg.Ciphertext == nil {
		ciphertextVal = corecbor.Null{}
	} else {
		ciphertextVal = corecbor.Bytes(msg.Ciphertext)
	}

	recipientsArr := make(corecbor.Array, len(msg.Recipients))
	for i, r := range msg.Recipients {
		rProtBytes, err := r.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if rProtBytes == nil {
			rProtBytes = []byte{}
		}
		rUnprotMap := r.Unprotected.toCBORMap()
		if rUnprotMap == nil {
			rUnprotMap = corecbor.Map{}
		}
		var rCipherVal corecbor.Value
		if r.Ciphertext == nil {
			rCipherVal = corecbor.Bytes(nil)
		} else {
			rCipherVal = corecbor.Bytes(r.Ciphertext)
		}
		recipientsArr[i] = corecbor.Array{
			corecbor.Bytes(rProtBytes),
			rUnprotMap,
			rCipherVal,
		}
	}

	arr := corecbor.Array{
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		ciphertextVal,
		recipientsArr,
	}

	tagged := corecbor.Tag{ID: tagEncrypt, Inner: arr}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, tagged)
}

func UnmarshalEncrypt(data []byte) (*Encrypt, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr corecbor.Array
	switch x := v.(type) {
	case corecbor.Tag:
		if x.ID != tagEncrypt {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, x.ID)
		}
		a, ok := x.Inner.(corecbor.Array)
		if !ok {
			return nil, fmt.Errorf("%w: tag 96 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.Array:
		arr = x
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Encrypt array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	protectedBstr, ok := arr[0].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected([]byte(protectedBstr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var ciphertext []byte
	switch c := arr[2].(type) {
	case corecbor.Bytes:
		ciphertext = []byte(c)
	case corecbor.Null:
		ciphertext = nil
	default:
		return nil, fmt.Errorf("%w: ciphertext must be bstr or null", ErrMalformed)
	}

	recipientsArr, ok := arr[3].(corecbor.Array)
	if !ok {
		return nil, fmt.Errorf("%w: recipients must be array", ErrMalformed)
	}

	recipients := make([]Recipient, len(recipientsArr))
	for i, rv := range recipientsArr {
		rArr, ok := rv.(corecbor.Array)
		if !ok || len(rArr) != 3 {
			return nil, fmt.Errorf("%w: recipient %d must be 3-element array", ErrMalformed, i)
		}

		rProtBstr, ok := rArr[0].(corecbor.Bytes)
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
		switch c := rArr[2].(type) {
		case corecbor.Bytes:
			rCiphertext = []byte(c)
		case corecbor.Null:
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
	if unprotectedMap == nil {
		unprotectedMap = corecbor.Map{}
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null{}
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	signaturesArr := make(corecbor.Array, len(msg.Signatures))
	for i, s := range msg.Signatures {
		sProtBytes, err := s.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if sProtBytes == nil {
			sProtBytes = []byte{}
		}
		sUnprotMap := s.Unprotected.toCBORMap()
		if sUnprotMap == nil {
			sUnprotMap = corecbor.Map{}
		}
		signaturesArr[i] = corecbor.Array{
			corecbor.Bytes(sProtBytes),
			sUnprotMap,
			corecbor.Bytes(s.Signature),
		}
	}

	arr := corecbor.Array{
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		signaturesArr,
	}

	tagged := corecbor.Tag{ID: tagSign, Inner: arr}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, tagged)
}

func UnmarshalSign(data []byte) (*Sign, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr corecbor.Array
	switch x := v.(type) {
	case corecbor.Tag:
		if x.ID != tagSign {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, x.ID)
		}
		a, ok := x.Inner.(corecbor.Array)
		if !ok {
			return nil, fmt.Errorf("%w: tag 98 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.Array:
		arr = x
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 4 {
		return nil, fmt.Errorf("%w: Sign array must have 4 elements, got %d", ErrMalformed, len(arr))
	}

	protectedBstr, ok := arr[0].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected([]byte(protectedBstr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch p := arr[2].(type) {
	case corecbor.Bytes:
		payload = []byte(p)
	case corecbor.Null:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	sigsArr, ok := arr[3].(corecbor.Array)
	if !ok {
		return nil, fmt.Errorf("%w: signatures must be array", ErrMalformed)
	}

	signatures := make([]Signature, len(sigsArr))
	for i, sv := range sigsArr {
		sArr, ok := sv.(corecbor.Array)
		if !ok || len(sArr) != 3 {
			return nil, fmt.Errorf("%w: signature %d must be 3-element array", ErrMalformed, i)
		}

		sProtBstr, ok := sArr[0].(corecbor.Bytes)
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

		sigBytes, ok := sArr[2].(corecbor.Bytes)
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
	if unprotectedMap == nil {
		unprotectedMap = corecbor.Map{}
	}

	var payloadVal corecbor.Value
	if msg.Payload == nil {
		payloadVal = corecbor.Null{}
	} else {
		payloadVal = corecbor.Bytes(msg.Payload)
	}

	recipientsArr := make(corecbor.Array, len(msg.Recipients))
	for i, r := range msg.Recipients {
		rProtBytes, err := r.Protected.encodeProtected()
		if err != nil {
			return nil, err
		}
		if rProtBytes == nil {
			rProtBytes = []byte{}
		}
		rUnprotMap := r.Unprotected.toCBORMap()
		if rUnprotMap == nil {
			rUnprotMap = corecbor.Map{}
		}
		var rCipherVal corecbor.Value
		if r.Ciphertext == nil {
			rCipherVal = corecbor.Bytes(nil)
		} else {
			rCipherVal = corecbor.Bytes(r.Ciphertext)
		}
		recipientsArr[i] = corecbor.Array{
			corecbor.Bytes(rProtBytes),
			rUnprotMap,
			rCipherVal,
		}
	}

	arr := corecbor.Array{
		corecbor.Bytes(protectedBytes),
		unprotectedMap,
		payloadVal,
		corecbor.Bytes(msg.Tag),
		recipientsArr,
	}

	tagged := corecbor.Tag{ID: tagMac, Inner: arr}
	enc := corecbor.New(corecbor.ModeCoreDeterministic)
	return enc.Encode(nil, tagged)
}

func UnmarshalMac(data []byte) (*Mac, error) {
	dec := corecbor.NewDecoder()
	v, err := dec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var arr corecbor.Array
	switch x := v.(type) {
	case corecbor.Tag:
		if x.ID != tagMac {
			return nil, fmt.Errorf("%w: unexpected tag %d", ErrMalformed, x.ID)
		}
		a, ok := x.Inner.(corecbor.Array)
		if !ok {
			return nil, fmt.Errorf("%w: tag 97 inner is not array", ErrMalformed)
		}
		arr = a
	case corecbor.Array:
		arr = x
	default:
		return nil, fmt.Errorf("%w: expected array or tag, got %T", ErrMalformed, v)
	}

	if len(arr) != 5 {
		return nil, fmt.Errorf("%w: Mac array must have 5 elements, got %d", ErrMalformed, len(arr))
	}

	protectedBstr, ok := arr[0].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: protected must be bstr", ErrMalformed)
	}

	prot, err := decodeProtected([]byte(protectedBstr))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	unprot, err := decodeUnprotected(arr[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}

	var payload []byte
	switch p := arr[2].(type) {
	case corecbor.Bytes:
		payload = []byte(p)
	case corecbor.Null:
		payload = nil
	default:
		return nil, fmt.Errorf("%w: payload must be bstr or null", ErrMalformed)
	}

	tag, ok := arr[3].(corecbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: tag must be bstr", ErrMalformed)
	}

	recipientsArr, ok := arr[4].(corecbor.Array)
	if !ok {
		return nil, fmt.Errorf("%w: recipients must be array", ErrMalformed)
	}

	recipients := make([]Recipient, len(recipientsArr))
	for i, rv := range recipientsArr {
		rArr, ok := rv.(corecbor.Array)
		if !ok || len(rArr) != 3 {
			return nil, fmt.Errorf("%w: recipient %d must be 3-element array", ErrMalformed, i)
		}

		rProtBstr, ok := rArr[0].(corecbor.Bytes)
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
		switch c := rArr[2].(type) {
		case corecbor.Bytes:
			rCiphertext = []byte(c)
		case corecbor.Null:
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
