// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package eat

import (
	"fmt"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/internal/asreceived"
)

// RFC 10013 measured-component media types and CoAP Content-Formats
// (§7.1, §7.2). In a CBOR EAT a measurements entry with
// ContentFormatMeasuredComponentCBOR carries an encoded measured
// component (mc-cbor); the JSON form (mc-json) is not decoded here.
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
// component when t is identified by ContentFormatMeasuredComponentCBOR;
// ok is false for any other content type.
func (t TypedBytes) MeasuredComponent() (m *MeasuredComponent, ok bool, err error) {
	if t.ContentFormat == nil || *t.ContentFormat != ContentFormatMeasuredComponentCBOR {
		return nil, false, nil
	}
	m, err = ParseMeasuredComponent(t.Value)
	return m, true, err
}
