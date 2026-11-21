// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor

import (
	"encoding/asn1"
	"fmt"
	"math"
	"math/bits"
	"net/netip"
	"strconv"
	"time"
)

// intOf returns v as an int64 when it is an integer in int64 range.
func intOf(v Value) (int64, bool) {
	switch v.Kind {
	case KindUint:
		if v.Num > math.MaxInt64 {
			return 0, false
		}
		return int64(v.Num), true
	case KindNegInt:
		if v.Num > math.MaxInt64 {
			return 0, false
		}
		return -1 - int64(v.Num), true
	default:
		return 0, false
	}
}

// intValue encodes n as Uint or NegInt.
func intValue(n int64) Value {
	if n >= 0 {
		return Uint(uint64(n))
	}
	return NegInt(uint64(-1 - n))
}

// expectTag checks that v is one of the given tags and returns its
// inner value.
func expectTag(v Value, what string, ids ...uint64) (Value, uint64, error) {
	if v.Kind == KindTag {
		for _, id := range ids {
			if v.TagID() == id {
				return v.TagInner(), id, nil
			}
		}
		return Value{}, 0, fmt.Errorf("%w: %s: unexpected tag %d", ErrMalformedTag, what, v.TagID())
	}
	return Value{}, 0, fmt.Errorf("%w: %s: expected a tag, got kind %d", ErrMalformedTag, what, v.Kind)
}

// --- RFC 9562 / tag 37: binary UUID ---

// UUIDTo returns Tag(37, Bytes(u[:])).
func UUIDTo(u [16]byte) Value {
	b := make([]byte, 16)
	copy(b, u[:])
	return MakeTag(TagUUID, Bytes(b))
}

// AsUUID requires tag 37 with a 16-byte byte string.
func AsUUID(t Value) ([16]byte, error) {
	var u [16]byte
	inner, _, err := expectTag(t, "UUID", TagUUID)
	if err != nil {
		return u, err
	}
	if inner.Kind != KindBytes || len(inner.BytesVal()) != 16 {
		return u, fmt.Errorf("%w: tag 37 content must be a 16-byte byte string", ErrMalformedTag)
	}
	copy(u[:], inner.BytesVal())
	return u, nil
}

// --- RFC 8943: dates ---

const secondsPerDay = 86400

// civilDays returns the days since 1970-01-01 of t's calendar date in
// t's location.
func civilDays(t time.Time) int64 {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / secondsPerDay
}

// DateTo returns Tag(1004, Text("YYYY-MM-DD")), the RFC 3339 full-date
// of t's calendar date in t's location (not converted to UTC). RFC 3339
// full-date has a four-digit year; for years outside 0000–9999 DateTo
// returns the equivalent tag 100 (DaysTo) form instead.
func DateTo(t time.Time) Value {
	if y := t.Year(); y < 0 || y > 9999 {
		return DaysTo(t)
	}
	return MakeTag(TagFullDate, Text(t.Format(time.DateOnly)))
}

// DaysTo returns Tag(100, n), where n is the number of days from
// 1970-01-01 to t's calendar date in t's location (negative before).
func DaysTo(t time.Time) Value {
	return MakeTag(TagDays, intValue(civilDays(t)))
}

// AsDate accepts tag 1004 (full-date) or tag 100 (days since
// 1970-01-01) and returns midnight UTC of that date. A day count
// outside time.Time's range returns an error wrapping ErrTimeRange.
func AsDate(t Value) (time.Time, error) {
	inner, id, err := expectTag(t, "date", TagFullDate, TagDays)
	if err != nil {
		return time.Time{}, err
	}
	if id == TagFullDate {
		if inner.Kind != KindText {
			return time.Time{}, fmt.Errorf("%w: tag 1004 content must be text", ErrMalformedTag)
		}
		d, err := time.Parse(time.DateOnly, inner.TextVal())
		if err != nil || d.Format(time.DateOnly) != inner.TextVal() {
			return time.Time{}, fmt.Errorf("%w: tag 1004 content %q is not an RFC 3339 full-date", ErrMalformedTag, inner.TextVal())
		}
		return d, nil
	}
	n, ok := intOf(inner)
	if !ok {
		if inner.Kind == KindUint || inner.Kind == KindNegInt {
			return time.Time{}, fmt.Errorf("%w: tag 100 day count out of range", ErrTimeRange)
		}
		return time.Time{}, fmt.Errorf("%w: tag 100 content must be an integer", ErrMalformedTag)
	}
	if n > math.MaxInt64/secondsPerDay || n < math.MinInt64/secondsPerDay {
		return time.Time{}, fmt.Errorf("%w: tag 100 day count %d", ErrTimeRange, n)
	}
	return time.Unix(n*secondsPerDay, 0).UTC(), nil
}

// --- RFC 9164 / tags 52, 54: IP addresses and prefixes ---

func ipTag(a netip.Addr) uint64 {
	if a.Is4() {
		return TagIPv4
	}
	return TagIPv6
}

// IPTo returns tag 52 (IPv4) or 54 (IPv6) with the address bytes
// (RFC 9164 Address Format). An IPv4-mapped IPv6 address stays IPv6;
// use a.Unmap() first for tag 52. A zone, if any, is written as the
// Interface Format [address, null, zone].
func IPTo(a netip.Addr) Value {
	b := a.AsSlice()
	if a.Zone() != "" {
		return MakeTag(ipTag(a), MakeArray(Bytes(b), Null(), zoneValue(a.Zone())))
	}
	return MakeTag(ipTag(a), Bytes(b))
}

// zoneValue writes a numeric zone as an integer (interface index) and
// any other zone as text (interface name), per RFC 9164 §3.1.3.
func zoneValue(z string) Value {
	if n, err := strconv.ParseUint(z, 10, 32); err == nil && strconv.FormatUint(n, 10) == z {
		return Uint(n)
	}
	return Text(z)
}

// PrefixTo returns the RFC 9164 Prefix Format [prefixlen, address
// bytes], with bits past the prefix length cleared and trailing zero
// bytes removed, as §4.2 requires.
func PrefixTo(p netip.Prefix) Value {
	p = p.Masked()
	b := p.Addr().AsSlice()
	n := len(b)
	for n > 0 && b[n-1] == 0 {
		n--
	}
	return MakeTag(ipTag(p.Addr()), MakeArray(Uint(uint64(p.Bits())), Bytes(b[:n])))
}

// InterfaceTo returns the RFC 9164 Interface Format [address,
// prefixlen]: the full interface address together with the length of
// its network prefix (p is not masked).
func InterfaceTo(p netip.Prefix) Value {
	a := p.Addr()
	items := []Value{Bytes(a.WithZone("").AsSlice()), Uint(uint64(p.Bits()))}
	if a.Zone() != "" {
		items = append(items, zoneValue(a.Zone()))
	}
	return MakeTag(ipTag(a), MakeArrayFromSlice(items))
}

func addrFrom(id uint64, b []byte) (netip.Addr, error) {
	want := 4
	if id == TagIPv6 {
		want = 16
	}
	if len(b) != want {
		return netip.Addr{}, fmt.Errorf("%w: tag %d address must be %d bytes, got %d", ErrMalformedTag, id, want, len(b))
	}
	a, _ := netip.AddrFromSlice(b)
	return a, nil
}

func withZone(a netip.Addr, z Value) (netip.Addr, error) {
	switch z.Kind {
	case KindText:
		return a.WithZone(z.TextVal()), nil
	case KindUint:
		return a.WithZone(strconv.FormatUint(z.UintVal(), 10)), nil
	default:
		return netip.Addr{}, fmt.Errorf("%w: zone identifier must be an integer or text", ErrMalformedTag)
	}
}

// AsIP decodes the RFC 9164 Address Format, or the address of the
// Interface Format (with its zone, if any).
func AsIP(t Value) (netip.Addr, error) {
	inner, id, err := expectTag(t, "IP address", TagIPv4, TagIPv6)
	if err != nil {
		return netip.Addr{}, err
	}
	switch inner.Kind {
	case KindBytes:
		return addrFrom(id, inner.BytesVal())
	case KindArray:
		items := inner.Array()
		if len(items) < 2 || len(items) > 3 || items[0].Kind != KindBytes {
			return netip.Addr{}, fmt.Errorf("%w: tag %d array is not an Interface Format", ErrMalformedTag, id)
		}
		a, err := addrFrom(id, items[0].BytesVal())
		if err != nil {
			return netip.Addr{}, err
		}
		if len(items) == 3 {
			return withZone(a, items[2])
		}
		return a, nil
	default:
		return netip.Addr{}, fmt.Errorf("%w: tag %d content must be a byte string or array", ErrMalformedTag, id)
	}
}

// AsPrefix decodes the RFC 9164 Prefix Format [prefixlen, bytes] (with
// the §4.3 checks: no trailing zero byte and no bits set past the
// prefix length, otherwise ErrNonCanonicalTag), the Interface Format
// [address, prefixlen] (returned unmasked), or the Address Format (a
// full-length prefix, /32 or /128).
func AsPrefix(t Value) (netip.Prefix, error) {
	inner, id, err := expectTag(t, "IP prefix", TagIPv4, TagIPv6)
	if err != nil {
		return netip.Prefix{}, err
	}
	size := 4
	if id == TagIPv6 {
		size = 16
	}
	if inner.Kind == KindBytes {
		a, err := addrFrom(id, inner.BytesVal())
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, size*8), nil
	}
	if inner.Kind != KindArray || len(inner.Array()) < 2 {
		return netip.Prefix{}, fmt.Errorf("%w: tag %d content must be a byte string or array", ErrMalformedTag, id)
	}
	items := inner.Array()
	if items[0].Kind == KindBytes { // Interface Format
		if len(items) > 3 || items[1].Kind != KindUint || items[1].UintVal() > uint64(size*8) {
			return netip.Prefix{}, fmt.Errorf("%w: tag %d Interface Format needs a prefix length 0..%d", ErrMalformedTag, id, size*8)
		}
		a, err := addrFrom(id, items[0].BytesVal())
		if err != nil {
			return netip.Prefix{}, err
		}
		if len(items) == 3 {
			if a, err = withZone(a, items[2]); err != nil {
				return netip.Prefix{}, err
			}
		}
		return netip.PrefixFrom(a, int(items[1].UintVal())), nil
	}
	if len(items) != 2 || items[0].Kind != KindUint || items[1].Kind != KindBytes {
		return netip.Prefix{}, fmt.Errorf("%w: tag %d Prefix Format is [prefixlen, bytes]", ErrMalformedTag, id)
	}
	plen, b := items[0].UintVal(), items[1].BytesVal()
	if plen > uint64(size*8) || len(b) > size {
		return netip.Prefix{}, fmt.Errorf("%w: tag %d prefix length or bytes too long", ErrMalformedTag, id)
	}
	if n := len(b); n > 0 && b[n-1] == 0 {
		return netip.Prefix{}, fmt.Errorf("%w: tag %d prefix bytes end in a zero byte", ErrNonCanonicalTag, id)
	}
	full := make([]byte, size)
	copy(full, b)
	// Every bit past the prefix length must be zero (RFC 9164 §4.3).
	for i := range full {
		bitStart := uint64(i * 8)
		if bitStart+8 <= plen {
			continue
		}
		var keep byte
		if bitStart < plen {
			keep = byte(0xff << (8 - (plen - bitStart)))
		}
		if full[i]&^keep != 0 {
			return netip.Prefix{}, fmt.Errorf("%w: tag %d prefix has bits set past /%d", ErrNonCanonicalTag, id, plen)
		}
	}
	a, _ := netip.AddrFromSlice(full)
	return netip.PrefixFrom(a, int(plen)), nil
}

// --- RFC 9090 / tags 110, 111, 112: object identifiers ---

// enterprisePrefix is the BER content of 1.3.6.1.4.1, which tag 112
// leaves out (RFC 9090 §2.2).
var enterprisePrefix = []byte{0x2b, 0x06, 0x01, 0x04, 0x01}

// appendArc appends n as a BER subidentifier (base 128, high bit set on
// all but the last byte).
func appendArc(b []byte, n uint64) []byte {
	var tmp [10]byte
	i := len(tmp) - 1
	tmp[i] = byte(n & 0x7f)
	for n >>= 7; n > 0; n >>= 7 {
		i--
		tmp[i] = byte(n&0x7f) | 0x80
	}
	return append(b, tmp[i:]...)
}

// berOID returns the BER content octets of an absolute OID.
func berOID(oid asn1.ObjectIdentifier) ([]byte, error) {
	if len(oid) < 2 || oid[0] < 0 || oid[0] > 2 || oid[1] < 0 || (oid[0] < 2 && oid[1] > 39) {
		return nil, fmt.Errorf("%w: OID %v must start with 0.x or 1.x (x < 40) or 2.x", ErrMalformedTag, oid)
	}
	first := uint64(oid[0])*40 + uint64(oid[1])
	b := appendArc(nil, first)
	for _, arc := range oid[2:] {
		if arc < 0 {
			return nil, fmt.Errorf("%w: OID %v has a negative arc", ErrMalformedTag, oid)
		}
		b = appendArc(b, uint64(arc))
	}
	return b, nil
}

// OIDTo returns the RFC 9090 preferred serialization of oid: tag 112
// with the arcs after 1.3.6.1.4.1 for OIDs under that arc (§2.2), and
// otherwise tag 111 with the BER content octets.
func OIDTo(oid asn1.ObjectIdentifier) (Value, error) {
	b, err := berOID(oid)
	if err != nil {
		return Value{}, err
	}
	if len(b) > len(enterprisePrefix) && string(b[:len(enterprisePrefix)]) == string(enterprisePrefix) {
		return MakeTag(TagEnterpriseOID, Bytes(b[len(enterprisePrefix):])), nil
	}
	return MakeTag(TagOID, Bytes(b)), nil
}

// RelativeOIDTo returns Tag(110, BER content of the relative OID arcs).
func RelativeOIDTo(arcs []uint64) Value {
	var b []byte
	for _, a := range arcs {
		b = appendArc(b, a)
	}
	return MakeTag(TagRelativeOID, Bytes(b))
}

// parseArcs splits BER subidentifiers, enforcing RFC 9090 §2.1: no
// subidentifier starts with 0x80, and the last byte ends a
// subidentifier. Arcs that don't fit 63 bits are rejected.
func parseArcs(b []byte, id uint64) ([]uint64, error) {
	var arcs []uint64
	var cur uint64
	start := true
	for _, c := range b {
		if start && c == 0x80 {
			return nil, fmt.Errorf("%w: tag %d subidentifier has a leading 0x80 byte", ErrNonCanonicalTag, id)
		}
		if bits.Len64(cur) > 63-7 {
			return nil, fmt.Errorf("%w: tag %d arc too large", ErrMalformedTag, id)
		}
		cur = cur<<7 | uint64(c&0x7f)
		start = c&0x80 == 0
		if start {
			arcs = append(arcs, cur)
			cur = 0
		}
	}
	if !start {
		return nil, fmt.Errorf("%w: tag %d ends inside a subidentifier", ErrMalformedTag, id)
	}
	return arcs, nil
}

func toOID(arcs []uint64, id uint64) (asn1.ObjectIdentifier, error) {
	oid := make(asn1.ObjectIdentifier, len(arcs))
	for i, a := range arcs {
		// parseArcs bounds arcs to 63 bits, which fits int on 64-bit
		// platforms.
		if bits.UintSize == 32 && a > math.MaxInt32 {
			return nil, fmt.Errorf("%w: tag %d arc %d too large", ErrMalformedTag, id, a)
		}
		oid[i] = int(a)
	}
	return oid, nil
}

// AsOID decodes tag 111 (absolute OID) or tag 112 (OID relative to
// 1.3.6.1.4.1) into an absolute object identifier.
func AsOID(t Value) (asn1.ObjectIdentifier, error) {
	inner, id, err := expectTag(t, "OID", TagOID, TagEnterpriseOID)
	if err != nil {
		return nil, err
	}
	if inner.Kind != KindBytes {
		return nil, fmt.Errorf("%w: tag %d content must be a byte string", ErrMalformedTag, id)
	}
	b := inner.BytesVal()
	if id == TagOID && len(b) == 0 {
		return nil, fmt.Errorf("%w: tag 111 content is empty", ErrMalformedTag)
	}
	arcs, err := parseArcs(b, id)
	if err != nil {
		return nil, err
	}
	if id == TagEnterpriseOID {
		return toOID(append([]uint64{1, 3, 6, 1, 4, 1}, arcs...), id)
	}
	first := arcs[0]
	var x, y uint64
	switch {
	case first < 40:
		x, y = 0, first
	case first < 80:
		x, y = 1, first-40
	default:
		x, y = 2, first-80
	}
	return toOID(append([]uint64{x, y}, arcs[1:]...), id)
}

// AsRelativeOID decodes tag 110 into its relative arcs (possibly none).
func AsRelativeOID(t Value) ([]uint64, error) {
	inner, id, err := expectTag(t, "relative OID", TagRelativeOID)
	if err != nil {
		return nil, err
	}
	if inner.Kind != KindBytes {
		return nil, fmt.Errorf("%w: tag 110 content must be a byte string", ErrMalformedTag)
	}
	return parseArcs(inner.BytesVal(), id)
}
