package cose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAESKW_RFC3394Vectors(t *testing.T) {
	tests := []struct {
		name string
		kek  string
		data string
		want string
	}{
		{
			name: "128-bit KEK, 128-bit data",
			kek:  "000102030405060708090A0B0C0D0E0F",
			data: "00112233445566778899AABBCCDDEEFF",
			want: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
		},
		{
			name: "192-bit KEK, 128-bit data",
			kek:  "000102030405060708090A0B0C0D0E0F1011121314151617",
			data: "00112233445566778899AABBCCDDEEFF",
			want: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
		},
		{
			name: "256-bit KEK, 192-bit data",
			kek:  "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			data: "00112233445566778899AABBCCDDEEFF0001020304050607",
			want: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kw := &AESKWKey{Key: mustDecodeHex(tt.kek)}
			data := mustDecodeHex(tt.data)
			want := mustDecodeHex(tt.want)

			wrapped, _, err := kw.WrapKey(data, KeyWrapOpts{})
			if err != nil {
				t.Fatalf("WrapKey error: %v", err)
			}
			if !bytes.Equal(wrapped, want) {
				t.Errorf("WrapKey = %X, want %X", wrapped, want)
			}
		})
	}
}

func TestAESKW_WrapUnwrap_RoundTrip(t *testing.T) {
	kek := make([]byte, 16)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}

	kw := &AESKWKey{Key: kek}
	wrapped, _, err := kw.WrapKey(cek, KeyWrapOpts{})
	if err != nil {
		t.Fatalf("WrapKey error: %v", err)
	}

	unwrapped, err := kw.UnwrapKey(wrapped, Headers{}, KeyUnwrapOpts{})
	if err != nil {
		t.Fatalf("UnwrapKey error: %v", err)
	}

	if !bytes.Equal(unwrapped, cek) {
		t.Errorf("round trip failed: got %X, want %X", unwrapped, cek)
	}
}

func TestAESKWDeriver_RoundTrip(t *testing.T) {
	for _, keyLen := range []int{16, 24, 32} {
		kek := make([]byte, keyLen)
		if _, err := rand.Read(kek); err != nil {
			t.Fatal(err)
		}

		cek := make([]byte, 16)
		if _, err := rand.Read(cek); err != nil {
			t.Fatal(err)
		}

		kw := &AESKWKey{Key: kek}
		wrapped, h, err := kw.WrapKey(cek, KeyWrapOpts{})
		if err != nil {
			t.Fatalf("keyLen=%d: WrapKey error: %v", keyLen, err)
		}

		unwrapped, err := kw.UnwrapKey(wrapped, h, KeyUnwrapOpts{})
		if err != nil {
			t.Fatalf("keyLen=%d: UnwrapKey error: %v", keyLen, err)
		}

		if !bytes.Equal(unwrapped, cek) {
			t.Errorf("keyLen=%d: got %X, want %X", keyLen, unwrapped, cek)
		}
	}
}

func TestECDHES_DeriveKey_RoundTrip(t *testing.T) {
	recipientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sender := &ECDHESKey{
		PeerPublic: recipientPriv.PublicKey(),
	}

	opts := KeyWrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16}
	derived, headers, err := sender.DeriveKey(opts)
	if err != nil {
		t.Fatalf("DeriveKey error: %v", err)
	}
	if len(derived) != 16 {
		t.Fatalf("derived key length = %d, want 16", len(derived))
	}

	receiver := &ECDHESKey{
		PrivateKey: recipientPriv,
	}
	unwrapOpts := KeyUnwrapOpts{CEKAlgorithm: AlgA128GCM, CEKLength: 16}
	rederived, err := receiver.UnderiveKey(headers, unwrapOpts)
	if err != nil {
		t.Fatalf("UnderiveKey error: %v", err)
	}

	if !bytes.Equal(derived, rederived) {
		t.Errorf("derived keys don't match: sender=%X receiver=%X", derived, rederived)
	}
}

func TestPBES2_RoundTrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}

	wrapper := &PBES2Key{Password: password}
	wrapped, headers, err := wrapper.WrapKey(cek, KeyWrapOpts{})
	if err != nil {
		t.Fatalf("WrapKey error: %v", err)
	}

	unwrapper := &PBES2Key{Password: password}
	unwrapped, err := unwrapper.UnwrapKey(wrapped, headers, KeyUnwrapOpts{})
	if err != nil {
		t.Fatalf("UnwrapKey error: %v", err)
	}

	if !bytes.Equal(unwrapped, cek) {
		t.Errorf("round trip failed: got %X, want %X", unwrapped, cek)
	}
}

func TestPBES2_WrongPassword(t *testing.T) {
	password := []byte("correct horse battery staple")
	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		t.Fatal(err)
	}

	wrapper := &PBES2Key{Password: password}
	wrapped, headers, err := wrapper.WrapKey(cek, KeyWrapOpts{})
	if err != nil {
		t.Fatalf("WrapKey error: %v", err)
	}

	wrongWrapper := &PBES2Key{Password: []byte("wrong password")}
	_, err = wrongWrapper.UnwrapKey(wrapped, headers, KeyUnwrapOpts{})
	if err == nil {
		t.Fatal("expected error with wrong password")
	}
	if err != ErrDecryption {
		t.Errorf("expected ErrDecryption, got %v", err)
	}
}

func TestEncryptMulti_TwoRecipients(t *testing.T) {
	plaintext := []byte("hello multi-recipient world")

	kek1 := make([]byte, 16)
	kek2 := make([]byte, 32)
	if _, err := rand.Read(kek1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(kek2); err != nil {
		t.Fatal(err)
	}

	r1 := &AESKWKey{Key: kek1}
	r2 := &AESKWKey{Key: kek2}

	msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{r1, r2})
	if err != nil {
		t.Fatalf("EncryptMulti error: %v", err)
	}

	if len(msg.Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(msg.Recipients))
	}

	decrypted1, err := DecryptMulti(msg, r1, 0)
	if err != nil {
		t.Fatalf("DecryptMulti recipient 0 error: %v", err)
	}
	if !bytes.Equal(decrypted1, plaintext) {
		t.Errorf("recipient 0: got %q, want %q", decrypted1, plaintext)
	}

	decrypted2, err := DecryptMulti(msg, r2, 1)
	if err != nil {
		t.Fatalf("DecryptMulti recipient 1 error: %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("recipient 1: got %q, want %q", decrypted2, plaintext)
	}
}

func TestEncryptMulti_ECDH_Recipient(t *testing.T) {
	plaintext := []byte("hello ECDH recipient")

	recipientPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sender := &ECDHESKey{
		PeerPublic: recipientPriv.PublicKey(),
	}

	msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{sender})
	if err != nil {
		t.Fatalf("EncryptMulti error: %v", err)
	}

	receiver := &ECDHESKey{
		PrivateKey: recipientPriv,
	}

	decrypted, err := DecryptMulti(msg, receiver, 0)
	if err != nil {
		t.Fatalf("DecryptMulti error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}

func TestMarshalEncrypt_Tagged(t *testing.T) {
	plaintext := []byte("test marshal encrypt")

	kek := make([]byte, 16)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}

	msg, err := EncryptMulti(plaintext, AlgA128GCM, []KeyDeriver{&AESKWKey{Key: kek}})
	if err != nil {
		t.Fatalf("EncryptMulti error: %v", err)
	}

	data, err := MarshalEncrypt(msg)
	if err != nil {
		t.Fatalf("MarshalEncrypt error: %v", err)
	}

	if data[0] != 0xD8 || data[1] != 96 {
		t.Errorf("expected CBOR tag 96, got first bytes %X %X", data[0], data[1])
	}

	decoded, err := UnmarshalEncrypt(data)
	if err != nil {
		t.Fatalf("UnmarshalEncrypt error: %v", err)
	}

	if len(decoded.Recipients) != 1 {
		t.Fatalf("expected 1 recipient after unmarshal, got %d", len(decoded.Recipients))
	}

	decrypted, err := DecryptMulti(decoded, &AESKWKey{Key: kek}, 0)
	if err != nil {
		t.Fatalf("DecryptMulti after unmarshal error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("got %q, want %q", decrypted, plaintext)
	}
}
