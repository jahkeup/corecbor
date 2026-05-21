package cose

import (
	"fmt"

	"github.com/jahkeup/corecbor"
)

const tagSign1 uint64 = 18

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
