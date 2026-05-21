package edhoc

import (
	"fmt"

	"github.com/jahkeup/corecbor/cbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

var encOpts = rfc8949.EncodeOpts{
	Deterministic: true,
	SortMode:      rfc8949.SortBytewiseLex,
	FloatMode:     rfc8949.FloatShortest,
}

func cborEncodeValue(buf []byte, v cbor.Value) ([]byte, error) {
	return rfc8949.Encode(buf, v, encOpts)
}

type message1 struct {
	Method    int64
	Suites    []CipherSuite // ordered preference; single suite encoded as int, multiple as array
	SuitesSel CipherSuite   // selected suite (first element) used for DH
	GX        []byte
	CI        []byte
}

type message2 struct {
	GY         []byte
	CR         []byte
	Ciphertext []byte
}

type message3 struct {
	Ciphertext []byte
}

func encodeMessage1(m *message1) ([]byte, error) {
	var buf []byte
	var err error

	buf, err = cborEncodeValue(buf, cbor.Uint(m.Method))
	if err != nil {
		return nil, fmt.Errorf("%w: encoding method: %v", ErrMessageFormat, err)
	}

	buf, err = encodeSuites(buf, m.Suites)
	if err != nil {
		return nil, fmt.Errorf("%w: encoding suites: %v", ErrMessageFormat, err)
	}

	buf, err = cborEncodeValue(buf, cbor.Bytes(m.GX))
	if err != nil {
		return nil, fmt.Errorf("%w: encoding G_X: %v", ErrMessageFormat, err)
	}
	buf, err = encodeConnectionID(buf, m.CI)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func encodeSuites(buf []byte, suites []CipherSuite) ([]byte, error) {
	if len(suites) == 1 {
		return cborEncodeValue(buf, cbor.Uint(uint64(suites[0])))
	}
	arr := make(cbor.Array, len(suites))
	for i, s := range suites {
		arr[i] = cbor.Uint(uint64(s))
	}
	return cborEncodeValue(buf, arr)
}

func decodeSuites(data []byte) ([]CipherSuite, CipherSuite, []byte, error) {
	v, rest, err := decodeOneValue(data)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: decoding suites: %v", ErrMessageFormat, err)
	}
	switch val := v.(type) {
	case cbor.Uint:
		s := CipherSuite(val)
		return []CipherSuite{s}, s, rest, nil
	case cbor.Array:
		if len(val) == 0 {
			return nil, 0, nil, fmt.Errorf("%w: empty suites array", ErrMessageFormat)
		}
		suites := make([]CipherSuite, len(val))
		for i, item := range val {
			u, ok := item.(cbor.Uint)
			if !ok {
				return nil, 0, nil, fmt.Errorf("%w: suite element must be uint", ErrMessageFormat)
			}
			suites[i] = CipherSuite(u)
		}
		return suites, suites[0], rest, nil
	default:
		return nil, 0, nil, fmt.Errorf("%w: suites must be uint or array", ErrMessageFormat)
	}
}

func decodeMessage1(data []byte) (*message1, error) {
	m := &message1{}

	method, rest, err := decodeOneValue(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding method: %v", ErrMessageFormat, err)
	}
	methodUint, ok := method.(cbor.Uint)
	if !ok {
		return nil, fmt.Errorf("%w: method must be uint", ErrMessageFormat)
	}
	m.Method = int64(methodUint)

	suites, selected, rest, err := decodeSuites(rest)
	if err != nil {
		return nil, err
	}
	m.Suites = suites
	m.SuitesSel = selected

	gx, rest, err := decodeOneValue(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding G_X: %v", ErrMessageFormat, err)
	}
	gxBytes, ok := gx.(cbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: G_X must be bstr", ErrMessageFormat)
	}
	m.GX = []byte(gxBytes)

	ci, _, err := decodeConnectionID(rest)
	if err != nil {
		return nil, err
	}
	m.CI = ci
	return m, nil
}

func encodeMessage2(m *message2) ([]byte, error) {
	var buf []byte
	var err error

	buf, err = cborEncodeValue(buf, cbor.Bytes(m.GY))
	if err != nil {
		return nil, fmt.Errorf("%w: encoding G_Y: %v", ErrMessageFormat, err)
	}
	buf, err = encodeConnectionID(buf, m.CR)
	if err != nil {
		return nil, err
	}
	buf, err = cborEncodeValue(buf, cbor.Bytes(m.Ciphertext))
	if err != nil {
		return nil, fmt.Errorf("%w: encoding ciphertext: %v", ErrMessageFormat, err)
	}
	return buf, nil
}

func decodeMessage2(data []byte) (*message2, error) {
	m := &message2{}

	gy, rest, err := decodeOneValue(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding G_Y: %v", ErrMessageFormat, err)
	}
	gyBytes, ok := gy.(cbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: G_Y must be bstr", ErrMessageFormat)
	}
	m.GY = []byte(gyBytes)

	cr, rest, err := decodeConnectionID(rest)
	if err != nil {
		return nil, err
	}
	m.CR = cr

	ct, _, err := decodeOneValue(rest)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding ciphertext: %v", ErrMessageFormat, err)
	}
	ctBytes, ok := ct.(cbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: ciphertext must be bstr", ErrMessageFormat)
	}
	m.Ciphertext = []byte(ctBytes)
	return m, nil
}

func encodeMessage3(m *message3) ([]byte, error) {
	var buf []byte
	var err error
	buf, err = cborEncodeValue(buf, cbor.Bytes(m.Ciphertext))
	if err != nil {
		return nil, fmt.Errorf("%w: encoding ciphertext: %v", ErrMessageFormat, err)
	}
	return buf, nil
}

func decodeMessage3(data []byte) (*message3, error) {
	ct, _, err := decodeOneValue(data)
	if err != nil {
		return nil, fmt.Errorf("%w: decoding ciphertext: %v", ErrMessageFormat, err)
	}
	ctBytes, ok := ct.(cbor.Bytes)
	if !ok {
		return nil, fmt.Errorf("%w: ciphertext must be bstr", ErrMessageFormat)
	}
	return &message3{Ciphertext: []byte(ctBytes)}, nil
}

// Connection IDs in EDHOC: integers -24..23 encode as the CBOR int directly,
// otherwise as a bstr. We use a simplified model: if len==1 and val<24, encode as int.
func encodeConnectionID(buf []byte, cid []byte) ([]byte, error) {
	if len(cid) == 1 && cid[0] < 24 {
		return cborEncodeValue(buf, cbor.Uint(cid[0]))
	}
	return cborEncodeValue(buf, cbor.Bytes(cid))
}

func decodeConnectionID(data []byte) ([]byte, []byte, error) {
	v, rest, err := decodeOneValue(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decoding connection ID: %v", ErrMessageFormat, err)
	}
	switch val := v.(type) {
	case cbor.Uint:
		return []byte{byte(val)}, rest, nil
	case cbor.Bytes:
		return []byte(val), rest, nil
	default:
		return nil, nil, fmt.Errorf("%w: connection ID must be int or bstr", ErrMessageFormat)
	}
}

func decodeOneValue(data []byte) (cbor.Value, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("%w: unexpected end of data", ErrMessageFormat)
	}
	v, n, err := rfc8949.Decode(data, rfc8949.DecodeOpts{})
	if err != nil {
		return nil, nil, err
	}
	return v, data[n:], nil
}

func encodeCBORArray(items ...cbor.Value) ([]byte, error) {
	return cborEncodeValue(nil, cbor.Array(items))
}
