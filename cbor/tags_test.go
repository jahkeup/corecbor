// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cbor_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/jahkeup/corecbor/cbor"
)

func TestAsTime_Tag0(t *testing.T) {
	tag := cbor.MakeTag(cbor.TagDateTimeString, cbor.Text("2023-06-15T12:30:00Z"))
	got, err := cbor.AsTime(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2023, 6, 15, 12, 30, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAsTime_Tag1_Integer(t *testing.T) {
	tag := cbor.MakeTag(cbor.TagEpochDateTime, cbor.Uint(1686830000))
	got, err := cbor.AsTime(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Unix(1686830000, 0).UTC()
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAsTime_Tag1_Float(t *testing.T) {
	tag := cbor.MakeTag(cbor.TagEpochDateTime, cbor.Float64(1686830000.5))
	got, err := cbor.AsTime(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Unix(1686830000, 500000000).UTC()
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAsTime_WrongTag(t *testing.T) {
	tag := cbor.MakeTag(99, cbor.Text("hello"))
	_, err := cbor.AsTime(tag)
	if err == nil {
		t.Fatal("expected error for wrong tag ID")
	}
}

func TestTimeTo_RoundTrip(t *testing.T) {
	orig := time.Date(2023, 6, 15, 12, 0, 0, 0, time.UTC)
	tag := cbor.TimeTo(orig)
	got, err := cbor.AsTime(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(orig) {
		t.Errorf("got %v, want %v", got, orig)
	}
}

func TestTimeToString_RoundTrip(t *testing.T) {
	orig := time.Date(2023, 6, 15, 12, 30, 0, 0, time.UTC)
	tag := cbor.TimeToString(orig)
	got, err := cbor.AsTime(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got.Equal(orig) {
		t.Errorf("got %v, want %v", got, orig)
	}
}

func TestAsBigInt_Tag2(t *testing.T) {
	tag := cbor.MakeTag(cbor.TagUnsignedBignum, cbor.Bytes([]byte{0x01, 0x00}))
	got, err := cbor.AsBigInt(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := big.NewInt(256)
	if got.Cmp(want) != 0 {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAsBigInt_Tag3(t *testing.T) {
	tag := cbor.MakeTag(cbor.TagNegativeBignum, cbor.Bytes([]byte{0x00}))
	got, err := cbor.AsBigInt(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := big.NewInt(-1)
	if got.Cmp(want) != 0 {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestBigIntTo_Positive(t *testing.T) {
	n := big.NewInt(1000)
	tag := cbor.BigIntTo(n)
	if tag.TagID() != cbor.TagUnsignedBignum {
		t.Fatalf("expected tag 2, got %d", tag.TagID())
	}
}

func TestBigIntTo_Negative(t *testing.T) {
	n := big.NewInt(-1000)
	tag := cbor.BigIntTo(n)
	if tag.TagID() != cbor.TagNegativeBignum {
		t.Fatalf("expected tag 3, got %d", tag.TagID())
	}
}

func TestBigIntTo_RoundTrip(t *testing.T) {
	cases := []*big.Int{
		big.NewInt(0),
		big.NewInt(12345678),
		big.NewInt(-99999),
	}
	for _, n := range cases {
		tag := cbor.BigIntTo(n)
		got, err := cbor.AsBigInt(tag)
		if err != nil {
			t.Fatalf("unexpected error for %v: %v", n, err)
		}
		if got.Cmp(n) != 0 {
			t.Errorf("round-trip failed: got %v, want %v", got, n)
		}
	}
}

func TestAsNestedCBOR_Tag24(t *testing.T) {
	inner := []byte{0xa1, 0x01, 0x02}
	tag := cbor.MakeTag(cbor.TagEncodedCBOR, cbor.Bytes(inner))
	got, err := cbor.AsNestedCBOR(tag)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(inner) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(inner))
	}
	for i := range got {
		if got[i] != inner[i] {
			t.Errorf("byte %d: got %x, want %x", i, got[i], inner[i])
		}
	}
}
