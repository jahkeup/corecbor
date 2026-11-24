// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/internal/asreceived"
)

// RFC 10013 measured-component media types and CoAP Content-Formats
// (§7.1, §7.2). In a CBOR EAT a measurements entry with
// ContentFormatMeasuredComponentCBOR carries an encoded measured
// component (mc-cbor) as a byte string, and one with
// ContentFormatMeasuredComponentJSON an mc-json text string.
const (
	MediaTypeMeasuredComponentCBOR = "application/measured-component+cbor"
	MediaTypeMeasuredComponentJSON = "application/measured-component+json"

	ContentFormatMeasuredComponentCBOR uint64 = 295
	ContentFormatMeasuredComponentJSON uint64 = 296
)

// measured-component map keys (RFC 10013 §4.3).
const (
	mcID          = 1
	mcDigested    = 2
	mcAuthorities = 3
	mcFlags       = 4
	mcRaw         = 5
)

// MeasuredComponent is an RFC 10013 measured component: an object in the
// attester's target environment and its measurement. Exactly one of
// Digest and Raw is set.
type MeasuredComponent struct {
	Name    string   // component-id name
	Version *Version // component-id version, optional

	Digest *ComponentDigest // digested-measurement (2)
	Raw    []byte           // raw-measurement (5)

	// Authorities identify the parties that signed the component
	// (§4.3.2); their meaning is profile defined. Optional.
	Authorities [][]byte
	// Flags is the profile-defined 64-bit field (§4.3.3): exactly 8
	// bytes, or nil when absent.
	Flags []byte
}

// ComponentDigest is RFC 10013 §4.2's digest. The algorithm is from the
// IANA Named Information Hash Algorithm registry, not COSE: Alg is the
// registry ID (1 is sha-256), or AlgName the hash name string when the
// text form is used.
type ComponentDigest struct {
	Alg     int64
	AlgName string
	Value   []byte
}

// ParseMeasuredComponent decodes an mc-cbor measured component (the
// value of a measurements entry with ContentFormatMeasuredComponentCBOR)
// and checks it against RFC 10013 §4: one CBOR map holding the
// component ID and exactly one of a digested or raw measurement, with
// optional non-empty authorities and 8-byte flags, and nothing else.
// Errors wrap ErrMalformedEAT.
func ParseMeasuredComponent(b []byte) (*MeasuredComponent, error) {
	if !asreceived.OneItem(b) {
		return nil, malformed("measured component must be one CBOR data item")
	}
	v, err := corecbor.NewDecoder(
		corecbor.WithoutInternalArena(),
		corecbor.RejectDuplicateMapKeys(),
		corecbor.WithMemoryBudget(decodeBudget),
	).Decode(b)
	if err != nil {
		return nil, fmt.Errorf("%w: measured component: %w", ErrMalformedEAT, err)
	}
	if v.Kind != corecbor.KindMap {
		return nil, malformed("measured component must be a map")
	}
	m := &MeasuredComponent{}
	var haveID bool
	for _, e := range v.Map() {
		k, ok := intKey(e.Key)
		if !ok {
			return nil, malformed("measured component member keys are integers")
		}
		switch k {
		case mcID:
			if err := m.parseID(e.Value); err != nil {
				return nil, err
			}
			haveID = true
		case mcDigested:
			d, err := parseComponentDigest(e.Value)
			if err != nil {
				return nil, err
			}
			m.Digest = d
		case mcRaw:
			if e.Value.Kind != corecbor.KindBytes {
				return nil, malformed("raw-measurement must be bytes")
			}
			m.Raw = e.Value.BytesVal()
		case mcAuthorities:
			items := e.Value.Array()
			if e.Value.Kind != corecbor.KindArray || len(items) == 0 {
				return nil, malformed("authorities must be a non-empty array")
			}
			for _, a := range items {
				if a.Kind != corecbor.KindBytes {
					return nil, malformed("authorities entries must be bytes")
				}
				m.Authorities = append(m.Authorities, a.BytesVal())
			}
		case mcFlags:
			if e.Value.Kind != corecbor.KindBytes || len(e.Value.BytesVal()) != 8 {
				return nil, malformed("flags must be 8 bytes")
			}
			m.Flags = e.Value.BytesVal()
		default:
			return nil, malformed("unknown measured component member %d", k)
		}
	}
	switch {
	case !haveID:
		return nil, malformed("measured component needs an id")
	case (m.Digest == nil) == (m.Raw == nil):
		return nil, malformed("measured component needs exactly one of digested-measurement and raw-measurement")
	}
	return m, nil
}

func (m *MeasuredComponent) parseID(v corecbor.Value) error {
	items := v.Array()
	if v.Kind != corecbor.KindArray || len(items) < 1 || len(items) > 2 || items[0].Kind != corecbor.KindText {
		return malformed("component-id must be [name, ?version]")
	}
	m.Name = items[0].TextVal()
	if len(items) == 2 {
		ver, err := parseVersion(items[1], "component-id version")
		if err != nil {
			return err
		}
		m.Version = ver
	}
	return nil
}

func parseComponentDigest(v corecbor.Value) (*ComponentDigest, error) {
	items := v.Array()
	if v.Kind != corecbor.KindArray || len(items) != 2 || items[1].Kind != corecbor.KindBytes {
		return nil, malformed("digested-measurement must be [alg, bytes]")
	}
	d := &ComponentDigest{Value: items[1].BytesVal()}
	switch items[0].Kind {
	case corecbor.KindText:
		d.AlgName = items[0].TextVal()
	case corecbor.KindUint, corecbor.KindNegInt:
		n, ok := intKey(items[0])
		if !ok {
			return nil, malformed("digest algorithm out of range")
		}
		d.Alg = n
	default:
		return nil, malformed("digest algorithm must be an integer or text")
	}
	return d, nil
}

// Encode writes m as an mc-cbor measured component in Core
// Deterministic encoding, after the checks ParseMeasuredComponent
// applies.
func (m *MeasuredComponent) Encode() ([]byte, error) {
	switch {
	case (m.Digest == nil) == (m.Raw == nil):
		return nil, malformed("measured component needs exactly one of Digest and Raw")
	case m.Flags != nil && len(m.Flags) != 8:
		return nil, malformed("flags must be 8 bytes")
	case m.Authorities != nil && len(m.Authorities) == 0:
		return nil, malformed("authorities must be non-empty when set")
	}
	id := []corecbor.Value{corecbor.Text(m.Name)}
	if m.Version != nil {
		id = append(id, versionValue(*m.Version))
	}
	entries := []corecbor.MapEntry{{Key: corecbor.Uint(mcID), Value: corecbor.MakeArrayFromSlice(id)}}
	if m.Digest != nil {
		alg := intValue(m.Digest.Alg)
		if m.Digest.AlgName != "" {
			alg = corecbor.Text(m.Digest.AlgName)
		}
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(mcDigested), Value: corecbor.MakeArray(alg, corecbor.Bytes(m.Digest.Value))})
	} else {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(mcRaw), Value: corecbor.Bytes(m.Raw)})
	}
	if len(m.Authorities) > 0 {
		as := make([]corecbor.Value, len(m.Authorities))
		for i, a := range m.Authorities {
			as[i] = corecbor.Bytes(a)
		}
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(mcAuthorities), Value: corecbor.MakeArrayFromSlice(as)})
	}
	if m.Flags != nil {
		entries = append(entries, corecbor.MapEntry{Key: corecbor.Uint(mcFlags), Value: corecbor.Bytes(m.Flags)})
	}
	b, err := encoder.Encode(nil, corecbor.MakeMapFromSlice(entries))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	return b, nil
}

// MeasuredComponent decodes t's value as an RFC 10013 measured
// component when t is identified by ContentFormatMeasuredComponentCBOR
// (a byte string holding mc-cbor) or ContentFormatMeasuredComponentJSON
// (a text string holding mc-json, the "tunnel" form in a CBOR EAT); ok
// is false for any other content type. A body of the wrong kind for its
// content format is an error.
func (t TypedBytes) MeasuredComponent() (m *MeasuredComponent, ok bool, err error) {
	if t.ContentFormat == nil {
		return nil, false, nil
	}
	switch *t.ContentFormat {
	case ContentFormatMeasuredComponentCBOR:
		if t.Text {
			return nil, true, malformed("measured-component+cbor body must be a byte string")
		}
		m, err = ParseMeasuredComponent(t.Value)
	case ContentFormatMeasuredComponentJSON:
		if !t.Text {
			return nil, true, malformed("measured-component+json body must be a text string in a CBOR EAT")
		}
		m, err = ParseMeasuredComponentJSON(t.Value)
	default:
		return nil, false, nil
	}
	return m, true, err
}

// JSON member names (RFC 10013 §4.3).
const (
	mcJSONID          = "id"
	mcJSONDigested    = "digested-measurement"
	mcJSONRaw         = "raw-measurement"
	mcJSONAuthorities = "authorities"
	mcJSONFlags       = "flags"
)

// b64u is RFC 10013's bytes-b64u: base64url without padding.
var b64u = base64.RawURLEncoding

// ParseMeasuredComponentJSON decodes an mc-json measured component
// (RFC 10013 §4, JSON data model) under the same rules as
// ParseMeasuredComponent: one JSON object with "id" and exactly one of
// "digested-measurement" and "raw-measurement", optional non-empty
// "authorities" and 8-byte "flags", no other or repeated members, byte
// values in unpadded base64url. Errors wrap ErrMalformedEAT.
func ParseMeasuredComponentJSON(b []byte) (*MeasuredComponent, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, malformed("measured component (JSON) must be an object")
	}
	m := &MeasuredComponent{}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, malformed("measured component (JSON): %v", err)
		}
		name, _ := tok.(string)
		if seen[name] {
			return nil, malformed("measured component (JSON): member %q repeated", name)
		}
		seen[name] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, malformed("measured component (JSON): %v", err)
		}
		if err := m.setJSONMember(name, raw); err != nil {
			return nil, err
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, malformed("measured component (JSON) is not a complete object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, malformed("measured component (JSON) has trailing data")
	}
	switch {
	case !seen[mcJSONID]:
		return nil, malformed("measured component needs an id")
	case (m.Digest == nil) == (m.Raw == nil):
		return nil, malformed("measured component needs exactly one of digested-measurement and raw-measurement")
	}
	return m, nil
}

func (m *MeasuredComponent) setJSONMember(name string, raw json.RawMessage) error {
	switch name {
	case mcJSONID:
		var id []json.RawMessage
		if err := json.Unmarshal(raw, &id); err != nil || len(id) < 1 || len(id) > 2 || json.Unmarshal(id[0], &m.Name) != nil {
			return malformed("component-id must be [name, ?version]")
		}
		if len(id) == 2 {
			var ver []json.RawMessage
			if err := json.Unmarshal(id[1], &ver); err != nil || len(ver) < 1 || len(ver) > 2 {
				return malformed("component-id version must be [version, ?scheme]")
			}
			v := &Version{}
			if json.Unmarshal(ver[0], &v.Version) != nil {
				return malformed("component-id version must be text")
			}
			if len(ver) == 2 {
				s, err := jsonInt(ver[1])
				if err != nil {
					return malformed("component-id version scheme: %v", err)
				}
				v.Scheme = &s
			}
			m.Version = v
		}
	case mcJSONDigested:
		var d []json.RawMessage
		if err := json.Unmarshal(raw, &d); err != nil || len(d) != 2 {
			return malformed("digested-measurement must be [alg, value]")
		}
		cd := &ComponentDigest{}
		if json.Unmarshal(d[0], &cd.AlgName) != nil {
			n, err := jsonInt(d[0])
			if err != nil {
				return malformed("digest algorithm must be an integer or text")
			}
			cd.Alg, cd.AlgName = n, ""
		}
		val, err := jsonBytes(d[1])
		if err != nil {
			return malformed("digest value: %v", err)
		}
		cd.Value = val
		m.Digest = cd
	case mcJSONRaw:
		val, err := jsonBytes(raw)
		if err != nil {
			return malformed("raw-measurement: %v", err)
		}
		m.Raw = val
	case mcJSONAuthorities:
		var as []json.RawMessage
		if err := json.Unmarshal(raw, &as); err != nil || len(as) == 0 {
			return malformed("authorities must be a non-empty array")
		}
		for _, a := range as {
			v, err := jsonBytes(a)
			if err != nil {
				return malformed("authorities: %v", err)
			}
			m.Authorities = append(m.Authorities, v)
		}
	case mcJSONFlags:
		v, err := jsonBytes(raw)
		if err != nil || len(v) != 8 {
			return malformed("flags must be 8 bytes")
		}
		m.Flags = v
	default:
		return malformed("unknown measured component member %q", name)
	}
	return nil
}

// jsonBytes decodes a bytes-b64u string (unpadded base64url).
func jsonBytes(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("want a base64url string")
	}
	b, err := b64u.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not unpadded base64url: %w", err)
	}
	return b, nil
}

// jsonInt decodes a JSON integer in the int64 range.
func jsonInt(raw json.RawMessage) (int64, error) {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("want an integer")
	}
	return strconv.ParseInt(n.String(), 10, 64)
}

// EncodeJSON writes m as an mc-json measured component, after the
// checks Encode applies. Byte values are unpadded base64url.
func (m *MeasuredComponent) EncodeJSON() ([]byte, error) {
	if _, err := m.Encode(); err != nil { // the same structural checks
		return nil, err
	}
	obj := map[string]any{}
	id := []any{m.Name}
	if m.Version != nil {
		ver := []any{m.Version.Version}
		if m.Version.Scheme != nil {
			ver = append(ver, *m.Version.Scheme)
		}
		id = append(id, ver)
	}
	obj[mcJSONID] = id
	if m.Digest != nil {
		var alg any = m.Digest.Alg
		if m.Digest.AlgName != "" {
			alg = m.Digest.AlgName
		}
		obj[mcJSONDigested] = []any{alg, b64u.EncodeToString(m.Digest.Value)}
	} else {
		obj[mcJSONRaw] = b64u.EncodeToString(m.Raw)
	}
	if len(m.Authorities) > 0 {
		as := make([]string, len(m.Authorities))
		for i, a := range m.Authorities {
			as[i] = b64u.EncodeToString(a)
		}
		obj[mcJSONAuthorities] = as
	}
	if m.Flags != nil {
		obj[mcJSONFlags] = b64u.EncodeToString(m.Flags)
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEAT, err)
	}
	return b, nil
}
