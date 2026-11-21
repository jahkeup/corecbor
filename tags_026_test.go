// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Proposal 026: tag helpers against the examples in their RFCs.

func enc026(t *testing.T, v Value) string {
	t.Helper()
	b, err := New(ModeCoreDeterministic).Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func dec026(t *testing.T, h string) Value {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewDecoder(WithoutInternalArena()).Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestUUIDTag(t *testing.T) {
	u := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	if got, want := enc026(t, UUIDTo(u)), "d825500123456789abcdef0123456789abcdef"; got != want {
		t.Fatalf("UUIDTo = %s, want %s", got, want)
	}
	back, err := AsUUID(UUIDTo(u))
	if err != nil || back != u {
		t.Fatalf("AsUUID = %x, %v", back, err)
	}
	if _, err := AsUUID(MakeTag(TagUUID, Bytes(make([]byte, 15)))); !errors.Is(err, ErrMalformedTag) {
		t.Fatalf("15-byte UUID err = %v", err)
	}
}

// RFC 8943 §1.1.1, Table 1.
func TestDateTags(t *testing.T) {
	cases := []struct {
		date time.Time
		full string
		days int64
	}{
		{time.Date(1940, 10, 9, 0, 0, 0, 0, time.UTC), "1940-10-09", -10676},
		{time.Date(1980, 12, 8, 0, 0, 0, 0, time.UTC), "1980-12-08", 3994},
	}
	for _, c := range cases {
		v := DateTo(c.date)
		if v.TagID() != TagFullDate || v.TagInner().TextVal() != c.full {
			t.Errorf("DateTo(%v) = %s", c.date, DiagnosticValue(v))
		}
		d := DaysTo(c.date)
		if n, _ := intOfTest(d.TagInner()); d.TagID() != TagDays || n != c.days {
			t.Errorf("DaysTo(%v) = %s, want %d", c.date, DiagnosticValue(d), c.days)
		}
		for _, tv := range []Value{v, d} {
			got, err := AsDate(tv)
			if err != nil || !got.Equal(c.date) {
				t.Errorf("AsDate(%s) = %v, %v", DiagnosticValue(tv), got, err)
			}
		}
	}
	// The civil date in the time's own location, not UTC.
	kiritimati := time.FixedZone("+14", 14*3600)
	if got := DateTo(time.Date(2024, 1, 1, 1, 0, 0, 0, kiritimati)).TagInner().TextVal(); got != "2024-01-01" {
		t.Errorf("DateTo(+14) = %s", got)
	}
	for _, bad := range []Value{
		MakeTag(TagFullDate, Text("2024-02-30")),
		MakeTag(TagFullDate, Text("2024-1-1")),
		MakeTag(TagFullDate, Uint(1)),
		MakeTag(TagDays, Text("x")),
	} {
		if _, err := AsDate(bad); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("AsDate(%s) err = %v", DiagnosticValue(bad), err)
		}
	}
	if _, err := AsDate(MakeTag(TagDays, NegInt(1<<62))); !errors.Is(err, ErrTimeRange) {
		t.Errorf("AsDate(huge) err = %v", err)
	}
	if v := DateTo(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)); v.TagID() != TagDays {
		t.Errorf("DateTo(year 10000) = %s, want tag 100", DiagnosticValue(v))
	}
}

func intOfTest(v Value) (int64, bool) {
	switch v.Kind {
	case KindUint:
		return int64(v.UintVal()), true
	case KindNegInt:
		return -1 - int64(v.NegIntVal()), true
	}
	return 0, false
}

// RFC 9164 §3.2, §3.3 and §4.
func TestIPTags(t *testing.T) {
	ip6 := netip.MustParseAddr("2001:db8:1234:deed:beef:cafe:face:feed")
	if got, want := enc026(t, IPTo(ip6)), "d83650"+"20010db81234deedbeefcafefacefeed"; got != want {
		t.Errorf("IPTo(v6) = %s, want %s", got, want)
	}
	ip4 := netip.MustParseAddr("192.0.2.1")
	if got, want := enc026(t, IPTo(ip4)), "d83444c0000201"; got != want {
		t.Errorf("IPTo(v4) = %s, want %s", got, want)
	}
	prefixes := []struct {
		p    string
		want string // diagnostic
	}{
		{"2001:db8:1234::/48", "54([48, h'20010db81234'])"},
		{"2001:db8:1230::/44", "54([44, h'20010db81230'])"},
		{"2001:db8::/64", "54([64, h'20010db8'])"},
		{"::/128", "54([128, h''])"},
		{"192.0.2.0/24", "52([24, h'c00002'])"},
	}
	for _, c := range prefixes {
		p := netip.MustParsePrefix(c.p)
		v := PrefixTo(p)
		if got := DiagnosticValue(v); got != c.want {
			t.Errorf("PrefixTo(%s) = %s, want %s", c.p, got, c.want)
		}
		back, err := AsPrefix(v)
		if err != nil || back != p {
			t.Errorf("AsPrefix(%s) = %v, %v", c.want, back, err)
		}
	}
	// Interface Format.
	iface := netip.MustParsePrefix("2001:db8:1234:deed:beef:cafe:face:feed/56")
	if got, want := DiagnosticValue(InterfaceTo(iface)), "54([h'20010db81234deedbeefcafefacefeed', 56])"; got != want {
		t.Errorf("InterfaceTo = %s, want %s", got, want)
	}
	if got, err := AsPrefix(InterfaceTo(iface)); err != nil || got != iface {
		t.Errorf("AsPrefix(interface) = %v, %v", got, err)
	}
	v4iface := netip.MustParsePrefix("192.0.2.1/24")
	if got := DiagnosticValue(InterfaceTo(v4iface)); got != "52([h'c0000201', 24])" {
		t.Errorf("InterfaceTo(v4) = %s", got)
	}
	// Zones: text, numeric, and address-only with null prefix length.
	ll := netip.MustParseAddr("fe80::202:2ff:ffff:fe03:303")
	for _, z := range []struct {
		zone string
		diag string
	}{
		{"eth0", `54([h'fe8000000000020202fffffffe030303', null, "eth0"])`},
		{"42", `54([h'fe8000000000020202fffffffe030303', null, 42])`},
	} {
		v := IPTo(ll.WithZone(z.zone))
		if got := DiagnosticValue(v); got != z.diag {
			t.Errorf("IPTo(zone %s) = %s, want %s", z.zone, got, z.diag)
		}
		if got, err := AsIP(v); err != nil || got != ll.WithZone(z.zone) {
			t.Errorf("AsIP(zone %s) = %v, %v", z.zone, got, err)
		}
	}
	// RFC 9164 §4.2/§4.3 invalid variants.
	for _, h := range []string{
		"d83682182c4620010db81233",   // 54([44, h'20010db81233']) bits past /44
		"d83682182c4620010db8123f",   // 54([44, h'20010db8123f'])
		"d83682182c4720010db8123012", // 54([44, h'20010db8123012'])
		"d83682182c4620010db81200",   // trailing zero byte
	} {
		if _, err := AsPrefix(dec026(t, h)); !errors.Is(err, ErrNonCanonicalTag) {
			t.Errorf("AsPrefix(%s) err = %v, want ErrNonCanonicalTag", h, err)
		}
	}
	for _, h := range []string{
		"d8364420010db8",     // 54(h'20010db8') wrong length
		"d83482182143c00002", // 52([33, ...]) prefix too long
		"d83443c00002",       // 52(h'c00002') wrong length
	} {
		if _, err := AsPrefix(dec026(t, h)); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("AsPrefix(%s) err = %v, want ErrMalformedTag", h, err)
		}
	}
}

// RFC 9090 §3.1, §3.2, §2.1, §2.2.
func TestOIDTags(t *testing.T) {
	sha256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	v, err := OIDTo(sha256)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := enc026(t, v), "d86f49608648016503040201"; got != want {
		t.Errorf("OIDTo(sha256) = %s, want %s", got, want)
	}
	if back, err := AsOID(v); err != nil || !back.Equal(sha256) {
		t.Errorf("AsOID = %v, %v", back, err)
	}
	// Preferred serialization: OIDs under 1.3.6.1.4.1 use tag 112.
	ent := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 1}
	v, err = OIDTo(ent)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := enc026(t, v), "d8704481fd5901"; got != want {
		t.Errorf("OIDTo(enterprise) = %s, want %s", got, want)
	}
	if back, err := AsOID(v); err != nil || !back.Equal(ent) {
		t.Errorf("AsOID(112) = %v, %v", back, err)
	}
	// The same OID in tag 111 form also decodes.
	if back, err := AsOID(dec026(t, "d86f492b0601040181fd5901")); err != nil || !back.Equal(ent) {
		t.Errorf("AsOID(111 enterprise) = %v, %v", back, err)
	}
	// Relative OID .1.1.29 (§3.2).
	if got, want := enc026(t, RelativeOIDTo([]uint64{1, 1, 29})), "d86e4301011d"; got != want {
		t.Errorf("RelativeOIDTo = %s, want %s", got, want)
	}
	if arcs, err := AsRelativeOID(dec026(t, "d86e4301011d")); err != nil || len(arcs) != 3 || arcs[2] != 29 {
		t.Errorf("AsRelativeOID = %v, %v", arcs, err)
	}
	if _, err := AsOID(dec026(t, "d86f43608086")); !errors.Is(err, ErrNonCanonicalTag) {
		t.Errorf("leading 0x80: err = %v", err)
	}
	if _, err := AsOID(dec026(t, "d86f43608648")); err != nil {
		t.Errorf("valid short OID: err = %v", err)
	}
	if _, err := AsOID(dec026(t, "d86f426086")); err == nil {
		t.Error("truncated arc: want error")
	}
	if _, err := OIDTo(asn1.ObjectIdentifier{3, 1}); !errors.Is(err, ErrMalformedTag) {
		t.Errorf("OIDTo(3.1) err = %v", err)
	}
}

// RFC 9581 §3.5.4 Figure 4 and §3.7 examples.
func TestExtendedTimeTag(t *testing.T) {
	m := MakeMap(
		MapEntry{Key: Uint(1), Value: Uint(1697724754)},
		MapEntry{Key: NegInt(5), Value: Uint(873294)}, // -6
		MapEntry{Key: NegInt(6), Value: MakeMap(MapEntry{Key: Uint(1), Value: Uint(0)}, MapEntry{Key: NegInt(5), Value: Uint(1000)})}, // -7
	)
	et, err := AsExtendedTime(MakeTag(TagExtendedTime, m))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(1697724754, 873294000).UTC(); !et.Time.Equal(want) {
		t.Errorf("Time = %v, want %v", et.Time, want)
	}
	if len(et.Extra) != 1 || et.Extra[0].Key.NegIntVal() != 6 {
		t.Errorf("Extra = %v", et.Extra)
	}
	// Re-encoding reproduces the RFC's key choice (-6 for microseconds).
	if got, want := DiagnosticValue(ExtendedTimeTo(et)), "1001({1: 1697724754, -6: 873294, -7: {1: 0, -6: 1000}})"; got != want {
		t.Errorf("ExtendedTimeTo = %s, want %s", got, want)
	}
	// §3.7: elective -10/-11 survive.
	ix := dec026(t, hexOf(t, MakeTag(TagExtendedTime, MakeMap(
		MapEntry{Key: Uint(1), Value: Uint(851042397)},
		MapEntry{Key: NegInt(9), Value: Text("America/Los_Angeles")},
		MapEntry{Key: NegInt(10), Value: MakeMap(MapEntry{Key: Text("u-ca"), Value: Text("hebrew")})},
	))))
	et, err = AsExtendedTime(ix)
	if err != nil || et.Time.Unix() != 851042397 || len(et.Extra) != 2 {
		t.Fatalf("IXDTF example: %+v, %v", et, err)
	}
	if !bytes.Equal(mustEnc(t, ExtendedTimeTo(et)), mustEnc(t, ix)) {
		t.Errorf("IXDTF round trip: %s vs %s", DiagnosticValue(ExtendedTimeTo(et)), DiagnosticValue(ix))
	}
	for name, bad := range map[string]Value{
		"no base":       MakeMap(MapEntry{Key: NegInt(9), Value: Text("x")}),
		"critical 2":    MakeMap(MapEntry{Key: Uint(1), Value: Uint(1)}, MapEntry{Key: Uint(2), Value: Uint(0)}),
		"decfrac 4":     MakeMap(MapEntry{Key: Uint(4), Value: MakeArray(NegInt(0), Uint(15))}),
		"two fractions": MakeMap(MapEntry{Key: Uint(1), Value: Uint(1)}, MapEntry{Key: NegInt(2), Value: Uint(1)}, MapEntry{Key: NegInt(5), Value: Uint(1)}),
		"float+frac":    MakeMap(MapEntry{Key: Uint(1), Value: Float64(1.5)}, MapEntry{Key: NegInt(2), Value: Uint(1)}),
		"TAI":           MakeMap(MapEntry{Key: Uint(1), Value: Uint(1)}, MapEntry{Key: Uint(13), Value: Uint(1)}),
		"pico":          MakeMap(MapEntry{Key: Uint(1), Value: Uint(1)}, MapEntry{Key: NegInt(11), Value: Uint(1)}),
	} {
		if _, err := AsExtendedTime(MakeTag(TagExtendedTime, bad)); !errors.Is(err, ErrMalformedTag) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// UTC timescale is accepted and kept.
	if et, err := AsExtendedTime(MakeTag(TagExtendedTime, MakeMap(MapEntry{Key: Uint(1), Value: Uint(5)}, MapEntry{Key: Uint(13), Value: Uint(0)}))); err != nil || len(et.Extra) != 1 {
		t.Errorf("UTC timescale: %+v, %v", et, err)
	}
}

func TestDurationTag(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		diag string
	}{
		{1500 * time.Millisecond, "1002({1: 1, -3: 500})"},
		{-1500 * time.Millisecond, "1002({1: -2, -3: 500})"},
		{3 * time.Second, "1002({1: 3})"},
		{time.Nanosecond, "1002({1: 0, -9: 1})"},
		{2*time.Second + 7*time.Microsecond, "1002({1: 2, -6: 7})"},
	} {
		v := DurationTo(c.d)
		if got := DiagnosticValue(v); got != c.diag {
			t.Errorf("DurationTo(%v) = %s, want %s", c.d, got, c.diag)
		}
		if back, err := AsDuration(v); err != nil || back != c.d {
			t.Errorf("AsDuration(%s) = %v, %v", c.diag, back, err)
		}
	}
	if _, err := AsDuration(MakeTag(TagDuration, MakeMap(MapEntry{Key: Uint(1), Value: Uint(1 << 40)}))); !errors.Is(err, ErrTimeRange) {
		t.Errorf("overflow err = %v", err)
	}
}

// RFC 9277 §2.3.1 example and App. B formula.
func TestRFC9277Labels(t *testing.T) {
	tn, err := ContentFormatTag(272)
	if err != nil || tn != 1668547090 {
		t.Fatalf("ContentFormatTag(272) = %d, %v", tn, err)
	}
	if got, want := enc026(t, SequenceLabelTo(tn)), "d9d9f8da6374021243424f52"; got != want {
		t.Errorf("SequenceLabelTo = %s, want %s", got, want)
	}
	if got, err := AsSequenceLabel(SequenceLabelTo(tn)); err != nil || got != tn {
		t.Errorf("AsSequenceLabel = %d, %v", got, err)
	}
	if got := enc026(t, TagWrappedTo(1330664270, Uint(1))); got != "d9d9f7da4f50534e01" {
		t.Errorf("TagWrappedTo = %s", got)
	}
	for ct := 0; ct < 65025; ct++ {
		tag, err := ContentFormatTag(uint16(ct))
		if err != nil {
			t.Fatal(err)
		}
		if back, ok := AsContentFormat(tag); !ok || int(back) != ct {
			t.Fatalf("AsContentFormat(TN(%d)) = %d, %v", ct, back, ok)
		}
	}
	if _, err := ContentFormatTag(65025); !errors.Is(err, ErrMalformedTag) {
		t.Errorf("ContentFormatTag(65025) err = %v", err)
	}
}

func TestEncodedCBORRoundTrip(t *testing.T) {
	inner := MakeMap(MapEntry{Key: Text("b"), Value: Uint(1)}, MapEntry{Key: Text("a"), Value: Uint(2)})
	w, err := New(ModeCoreDeterministic).EncodeEncodedCBOR(inner)
	if err != nil {
		t.Fatal(err)
	}
	if got := enc026(t, w); got != "d81847a2616102616201" {
		t.Errorf("EncodeEncodedCBOR = %s", got)
	}
	// Received non-canonical bytes are returned exactly.
	foreign := WrapEncodedCBOR([]byte{0xa2, 0x61, 'b', 0x01, 0x61, 'a', 0x02})
	v, raw, err := NewDecoder().DecodeEncodedCBOR(foreign)
	if err != nil || !bytes.Equal(raw, foreign.TagInner().BytesVal()) || len(v.Map()) != 2 {
		t.Fatalf("DecodeEncodedCBOR = %v, %x, %v", v, raw, err)
	}
	if _, _, err := NewDecoder().DecodeEncodedCBOR(WrapEncodedCBOR([]byte{0x01, 0x02})); !errors.Is(err, ErrTrailingBytes) {
		t.Errorf("two items: err = %v", err)
	}
	if _, _, err := NewDecoder().DecodeEncodedCBOR(Uint(1)); !errors.Is(err, ErrMalformedTag) {
		t.Errorf("not a tag: err = %v", err)
	}
}

func hexOf(t *testing.T, v Value) string { t.Helper(); return hex.EncodeToString(mustEnc(t, v)) }

func mustEnc(t *testing.T, v Value) []byte {
	t.Helper()
	b, err := New(ModeCoreDeterministic).Encode(nil, v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
