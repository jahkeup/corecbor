package corecbor

import (
	"bytes"
	"testing"
)

func TestRawMessage_RoundTrip(t *testing.T) {
	type Envelope struct {
		Type    string     `cbor:"type"`
		Payload RawMessage `cbor:"payload"`
	}

	inner, err := Marshal("hello")
	if err != nil {
		t.Fatal(err)
	}

	orig := Envelope{Type: "test", Payload: RawMessage(inner)}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != orig.Type {
		t.Errorf("Type = %q, want %q", got.Type, orig.Type)
	}
	if !bytes.Equal(got.Payload, orig.Payload) {
		t.Errorf("Payload = %x, want %x", got.Payload, orig.Payload)
	}
}

func TestRawMessage_Nil(t *testing.T) {
	type Envelope struct {
		Payload RawMessage `cbor:"payload"`
	}

	data, err := Marshal(Envelope{Payload: nil})
	if err != nil {
		t.Fatal(err)
	}

	nullData, err := Marshal(struct {
		Payload any `cbor:"payload"`
	}{Payload: nil})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, nullData) {
		t.Errorf("nil RawMessage encoded as %x, want null encoding %x", data, nullData)
	}
}

func TestRawMessage_DeferredDecode(t *testing.T) {
	type Inner struct {
		X int `cbor:"x"`
	}
	type Envelope struct {
		Payload RawMessage `cbor:"payload"`
	}

	innerData, err := Marshal(Inner{X: 42})
	if err != nil {
		t.Fatal(err)
	}

	env := Envelope{Payload: RawMessage(innerData)}
	data, err := Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	var got Envelope
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	var inner Inner
	if err := Unmarshal(got.Payload, &inner); err != nil {
		t.Fatal(err)
	}
	if inner.X != 42 {
		t.Errorf("inner.X = %d, want 42", inner.X)
	}
}

func TestRawMessage_InMap(t *testing.T) {
	innerData, err := Marshal(123)
	if err != nil {
		t.Fatal(err)
	}

	m := map[string]RawMessage{
		"a": RawMessage(innerData),
	}
	data, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]RawMessage
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got["a"], innerData) {
		t.Errorf("got[a] = %x, want %x", got["a"], innerData)
	}
}

func TestRawTag_RoundTrip(t *testing.T) {
	innerData, err := Marshal("https://example.com")
	if err != nil {
		t.Fatal(err)
	}

	orig := RawTag{ID: 32, Content: RawMessage(innerData)}
	data, err := Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var got RawTag
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != orig.ID {
		t.Errorf("ID = %d, want %d", got.ID, orig.ID)
	}
	if !bytes.Equal(got.Content, orig.Content) {
		t.Errorf("Content = %x, want %x", got.Content, orig.Content)
	}
}

func TestRawTag_InnerPreserved(t *testing.T) {
	innerData, err := Marshal(uint64(12345))
	if err != nil {
		t.Fatal(err)
	}

	rt := RawTag{ID: 100, Content: RawMessage(innerData)}
	data, err := Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}

	var got RawTag
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Content, innerData) {
		t.Errorf("Content bytes not preserved: got %x, want %x", got.Content, innerData)
	}
}

func TestRawTag_NilContent(t *testing.T) {
	rt := RawTag{ID: 55, Content: nil}
	data, err := Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}

	var got RawTag
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 55 {
		t.Errorf("ID = %d, want 55", got.ID)
	}

	nullBytes, _ := Marshal(nil)
	if !bytes.Equal(got.Content, nullBytes) {
		t.Errorf("nil Content decoded as %x, want null encoding %x", got.Content, nullBytes)
	}
}

func TestStructTag_TagWrap(t *testing.T) {
	type S struct {
		URL string `cbor:"url,tag=32"`
	}

	data, err := Marshal(S{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}

	var rt RawTag
	type Wrapper struct {
		URL RawTag `cbor:"url"`
	}
	var w Wrapper
	if err := Unmarshal(data, &w); err != nil {
		t.Fatal(err)
	}
	rt = w.URL
	if rt.ID != 32 {
		t.Errorf("tag ID = %d, want 32", rt.ID)
	}

	var url string
	if err := Unmarshal(rt.Content, &url); err != nil {
		t.Fatal(err)
	}
	if url != "https://example.com" {
		t.Errorf("url = %q, want %q", url, "https://example.com")
	}
}

func TestStructTag_TagUnwrap(t *testing.T) {
	type S struct {
		URL string `cbor:"url,tag=32"`
	}

	data, err := Marshal(S{URL: "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}

	var got S
	if err := Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.URL != "https://example.com" {
		t.Errorf("URL = %q, want %q", got.URL, "https://example.com")
	}
}

func TestStructTag_WrongTagID(t *testing.T) {
	type Tagged99 struct {
		X string `cbor:"x,tag=99"`
	}
	type Tagged32 struct {
		X string `cbor:"x,tag=32"`
	}

	data, err := Marshal(Tagged99{X: "hello"})
	if err != nil {
		t.Fatal(err)
	}

	var got Tagged32
	err = Unmarshal(data, &got)
	if err == nil {
		t.Fatal("expected error for wrong tag ID, got nil")
	}
}

func TestStructTag_NotATag(t *testing.T) {
	type Plain struct {
		X string `cbor:"x"`
	}
	type Tagged struct {
		X string `cbor:"x,tag=32"`
	}

	data, err := Marshal(Plain{X: "hello"})
	if err != nil {
		t.Fatal(err)
	}

	var got Tagged
	err = Unmarshal(data, &got)
	if err == nil {
		t.Fatal("expected error for non-tagged value into tag field, got nil")
	}
}
