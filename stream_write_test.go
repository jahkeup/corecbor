// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package corecbor

import (
	"bytes"
	"io"
	"math"
	"testing"
)

func TestStreamWriteUint(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(3)
	s.WriteUint(0)
	s.WriteUint(255)
	s.WriteUint(65536)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Uint(0), Uint(255), Uint(65536)})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteNegInt(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(2)
	s.WriteNegInt(0)
	s.WriteNegInt(999)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{NegInt(0), NegInt(999)})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteBytes(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(2)
	s.WriteBytes([]byte{0xde, 0xad})
	s.WriteBytes(nil)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Bytes{0xde, 0xad}, Bytes(nil)})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteText(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(2)
	s.WriteText("hello")
	s.WriteText("")
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Text("hello"), Text("")})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteTextRejectsInvalidUTF8(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(1)
	err := s.WriteText("\x80invalid")
	if err == nil {
		t.Fatal("expected error for invalid UTF-8")
	}
}

func TestStreamWriteTextAllowsInvalidUTF8(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive, AllowInvalidUTF8())
	s := enc.Stream(&buf)
	s.BeginArray(1)
	err := s.WriteText("\x80invalid")
	if err != nil {
		t.Fatalf("AllowInvalidUTF8 should permit: %v", err)
	}
	s.EndContainer()
}

func TestStreamWriteBoolNullUndefined(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(4)
	s.WriteBool(true)
	s.WriteBool(false)
	s.WriteNull()
	s.WriteUndefined()
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Bool(true), Bool(false), Null{}, Undefined{}})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteFloat(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(2)
	s.WriteFloat32(1.5)
	s.WriteFloat64(3.14159)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Float32(1.5), Float64(3.14159)})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteFloatRejectsNaN(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(1)
	err := s.WriteFloat64(math.NaN())
	if err == nil {
		t.Fatal("expected error for NaN")
	}
}

func TestStreamWriteSimple(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(2)
	s.WriteSimple(16)
	s.WriteSimple(255)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Simple(16), Simple(255)})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteTag(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginArray(1)
	s.WriteTag(1)
	s.WriteUint(1000)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{Tag{ID: 1, Inner: Uint(1000)}})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteRawCBOR(t *testing.T) {
	enc := New(ModePermissive)
	preEncoded, _ := enc.Encode(nil, Map{
		{Key: Text("x"), Value: Uint(1)},
	})

	var buf bytes.Buffer
	s := enc.Stream(&buf)
	s.BeginArray(2)
	s.WriteUint(42)
	s.WriteRawCBOR(preEncoded)
	s.EndContainer()

	expected, _ := enc.Encode(nil, Array{
		Uint(42),
		Map{{Key: Text("x"), Value: Uint(1)}},
	})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func TestStreamWriteMapDirect(t *testing.T) {
	var buf bytes.Buffer
	enc := New(ModePermissive)
	s := enc.Stream(&buf)
	s.BeginMap(2)
	s.WriteText("id")
	s.WriteUint(42)
	s.WriteText("data")
	s.WriteBytes([]byte{0x01, 0x02})
	s.EndContainer()

	expected, _ := enc.Encode(nil, Map{
		{Key: Text("id"), Value: Uint(42)},
		{Key: Text("data"), Value: Bytes{0x01, 0x02}},
	})
	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("got %x, want %x", buf.Bytes(), expected)
	}
}

func BenchmarkStreamWriteUint(b *testing.B) {
	enc := New(ModePermissive)
	s := enc.Stream(io.Discard)
	b.ResetTimer()
	for range b.N {
		s.WriteUint(42) //nolint:errcheck
	}
}

func BenchmarkStreamWriteText(b *testing.B) {
	enc := New(ModePermissive)
	s := enc.Stream(io.Discard)
	b.ResetTimer()
	for range b.N {
		s.WriteText("hello") //nolint:errcheck
	}
}

func BenchmarkStreamWriteBytes(b *testing.B) {
	enc := New(ModePermissive)
	payload := make([]byte, 64)
	s := enc.Stream(io.Discard)
	b.ResetTimer()
	for range b.N {
		s.WriteBytes(payload) //nolint:errcheck
	}
}

func BenchmarkStreamWriteValueUint(b *testing.B) {
	enc := New(ModePermissive)
	s := enc.Stream(io.Discard)
	v := Uint(42)
	b.ResetTimer()
	for range b.N {
		s.WriteValue(v) //nolint:errcheck
	}
}
