// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/jahkeup/corecbor"
)

// Proposal 028 Phase 2: COSE_Key parse/marshal, KeySet, key_ops,
// thumbprint.

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// W3C WebAuthn Level 3 §16.7 "Packed Attestation with ES256 Credential"
// (https://w3c.github.io/webauthn/, fetched 2026-11-21).
const (
	webauthnES256AuthData = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54d00000000876ca4f52071c3e9b25509ef2cdf7ed60020c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423"
	webauthnES256CredPriv = "36ed7bea2357cefa8c4ec7e134f3312d2e6ca3058519d0bcb4c1424272010432"
	webauthnES256AssnData = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000"
	webauthnES256AssnCDJ  = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273524276704770587676463446524841565833496d4b4130453958773858306b526a44426c4d6668726255222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20415a4d77794d78496244382d756775464e7036723851227d"
	webauthnES256AssnSig  = "30450220694969d3ee928de6f02ef23a9c644d7d779916451734a94b432542f498a1ebe90221008b0819c824218a97152cd099c55bfb1477b29d900a49a64018314f9bfccda163"
)

func TestParseKeyPrefixWebAuthn(t *testing.T) {
	authData := mustHexBytes(t, webauthnES256AuthData)
	// rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId(32)
	credKey := authData[32+1+4+16+2+32:]
	// Attested credential data may be followed by extensions (flag ED).
	ext := []byte{0xa1, 0x6b, 'c', 'r', 'e', 'd', 'P', 'r', 'o', 't', 'e', 'c', 't', 0x02}
	for name, tail := range map[string][]byte{"no-extensions": nil, "extensions": ext} {
		t.Run(name, func(t *testing.T) {
			k, rest, err := ParseKeyPrefix(append(bytes.Clone(credKey), tail...))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rest, tail) {
				t.Fatalf("rest = %x, want %x", rest, tail)
			}
			if a, ok := k.Algorithm(); !ok || a != AlgES256 {
				t.Fatalf("alg = %v, %v", a, ok)
			}
			pub, err := k.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			// The parsed key is the one the spec's private key implies.
			priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), mustHexBytes(t, webauthnES256CredPriv))
			if err != nil {
				t.Fatal(err)
			}
			if !priv.PublicKey.Equal(pub) {
				t.Fatal("parsed key differs from the vector's credential key")
			}
			// And it verifies the vector's assertion signature.
			cdj := sha256.Sum256(mustHexBytes(t, webauthnES256AssnCDJ))
			signed := append(mustHexBytes(t, webauthnES256AssnData), cdj[:]...)
			digest := sha256.Sum256(signed)
			if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], mustHexBytes(t, webauthnES256AssnSig)) {
				t.Fatal("assertion signature does not verify with the parsed key")
			}
		})
	}
}

// ParseKey shares one decoder; concurrent parses must not race (-race).
func TestParseKeyConcurrent(t *testing.T) {
	data := mustHexBytes(t, webauthnES256AuthData)[32+1+4+16+2+32:]
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				if _, _, err := ParseKeyPrefix(data); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// RFC 9679 §6.
func TestThumbprintRFC9679(t *testing.T) {
	k, err := ParseKey(mustHexBytes(t, "A50102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C025820496BD8AFADF307E5B08C64B0421BF9DC01528A344A43BDA88FADD1669DA253EC"))
	if err != nil {
		t.Fatal(err)
	}
	tp, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tp) != "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec" {
		t.Fatalf("thumbprint = %x", tp)
	}
	// The kid in the example is the thumbprint itself.
	if !bytes.Equal(tp, k.ID()) {
		t.Fatal("thumbprint differs from the example's kid")
	}
}

func TestKeyRoundTrip(t *testing.T) {
	var keys []*Key
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, _ := ecdsa.GenerateKey(c, rand.Reader)
		k, err := NewKeyFromSigner(priv)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
		pub, _ := NewKeyFromPublic(&priv.PublicKey)
		keys = append(keys, pub)
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	ed, _ := NewKeyFromSigner(edPriv)
	keys = append(keys, ed)
	xpriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	keys = append(keys, &Key{params: map[int64]any{
		keyLabelKty: int64(KeyTypeOKP), keyLabelCrv: int64(CurveX25519),
		keyLabelX: xpriv.PublicKey().Bytes(), keyLabelD: xpriv.Bytes(),
	}})
	keys = append(keys, &Key{params: map[int64]any{
		keyLabelKty: int64(KeyTypeSymmetric), keyLabelSymK: bytes.Repeat([]byte{7}, 16), keyLabelKid: []byte("sym"),
	}})
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys = append(keys, &Key{params: map[int64]any{
		keyLabelKty: int64(KeyTypeRSA), keyLabelRSAN: rk.N.Bytes(), keyLabelRSAE: []byte{1, 0, 1},
	}})
	keys = append(keys, &Key{params: map[int64]any{
		keyLabelKty: int64(KeyTypeAKP), keyLabelAlg: int64(-48), keyLabelAKPPub: bytes.Repeat([]byte{1}, 1312),
	}})
	for i, k := range keys {
		enc, err := k.MarshalCBOR()
		if err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
		got, err := ParseKey(enc)
		if err != nil {
			t.Fatalf("key %d (kty %d): ParseKey: %v", i, k.KeyType(), err)
		}
		enc2, err := got.MarshalCBOR()
		if err != nil || !bytes.Equal(enc, enc2) {
			t.Fatalf("key %d: round trip changed bytes:\n%x\n%x", i, enc, enc2)
		}
		if _, err := got.Thumbprint(crypto.SHA256); err != nil {
			t.Fatalf("key %d: Thumbprint: %v", i, err)
		}
	}
}

func p256Coords(t *testing.T) (x, y []byte, priv *ecdsa.PrivateKey) {
	t.Helper()
	// Find a key whose x has a leading zero byte.
	for {
		p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		raw, _ := p.PublicKey.Bytes()
		if raw[1] == 0 {
			return raw[1:33], raw[33:], p
		}
	}
}

func ec2KeyBytes(t *testing.T, x, y any) []byte {
	t.Helper()
	k := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeEC2), keyLabelCrv: int64(CurveP256), keyLabelX: x, keyLabelY: y}}
	b, err := k.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeyCoordinateLength(t *testing.T) {
	x, y, priv := p256Coords(t)
	short := x[1:] // leading zero stripped: 31 bytes
	long := append([]byte{0}, x...)

	if _, err := ParseKey(ec2KeyBytes(t, short, y)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("short x: %v, want ErrInvalidKey", err)
	}
	k, err := ParseKey(ec2KeyBytes(t, short, y), AllowShortCoordinates())
	if err != nil {
		t.Fatalf("short x with AllowShortCoordinates: %v", err)
	}
	pub, err := k.PublicKey()
	if err != nil || !priv.PublicKey.Equal(pub) {
		t.Fatalf("padded key differs: %v", err)
	}
	if _, err := ParseKey(ec2KeyBytes(t, long, y), AllowShortCoordinates()); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("long x: %v, want ErrInvalidKey", err)
	}

	// (*Key).PublicKey keeps v0.2.2's left-padding of short coordinates
	// and now rejects long ones.
	legacy := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeEC2), keyLabelCrv: int64(CurveP256), keyLabelX: short, keyLabelY: y}}
	if pub, err := legacy.PublicKey(); err != nil || !priv.PublicKey.Equal(pub) {
		t.Fatalf("PublicKey short x: %v", err)
	}
	legacy.params[keyLabelX] = long
	if _, err := legacy.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("PublicKey long x: %v, want ErrInvalidKey", err)
	}
}

func TestKeyCompressedPoint(t *testing.T) {
	for range 8 {
		p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		raw, _ := p.PublicKey.Bytes()
		x, y := raw[1:33], raw[33:]
		odd := y[31]&1 == 1
		k, err := ParseKey(ec2KeyBytes(t, x, odd))
		if err != nil {
			t.Fatal(err)
		}
		pub, err := k.PublicKey()
		if err != nil || !p.PublicKey.Equal(pub) {
			t.Fatalf("decompressed key differs: %v", err)
		}
		full, _ := ParseKey(ec2KeyBytes(t, x, y))
		a, _ := k.Thumbprint(crypto.SHA256)
		b, _ := full.Thumbprint(crypto.SHA256)
		if !bytes.Equal(a, b) {
			t.Fatal("compressed and uncompressed thumbprints differ")
		}
	}
}

func TestParseKeyRejects(t *testing.T) {
	cases := map[string]string{
		"not a map":     "80",
		"no kty":        "a1200a",
		"unknown kty":   "a10118ff",
		"dup label":     "a20101" + "0101",
		"okp short x":   "a3010120062141aa",
		"sym empty k":   "a201042040",
		"akp no alg":    "a2010720410a",
		"rsa small n":   "a3010320410a2143010001",
		"trailing byte": "a201042041aa" + "00",
	}
	for name, h := range cases {
		if _, err := ParseKey(mustHexBytes(t, h)); err == nil {
			t.Errorf("%s: ParseKey succeeded", name)
		} else if !errors.Is(err, ErrInvalidKey) && !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrInvalidKey or ErrMalformed", name, err)
		}
	}
	// A private key must match its public part.
	_, a, _ := ed25519.GenerateKey(rand.Reader)
	_, b, _ := ed25519.GenerateKey(rand.Reader)
	mixed := &Key{params: map[int64]any{
		keyLabelKty: int64(KeyTypeOKP), keyLabelCrv: int64(CurveEd25519),
		keyLabelX: []byte(a.Public().(ed25519.PublicKey)), keyLabelD: b.Seed(),
	}}
	enc, _ := mixed.MarshalCBOR()
	if _, err := ParseKey(enc); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("mismatched d/x: %v", err)
	}
}

func TestKeyOpsEnforced(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := NewKeyFromSigner(priv)
	k.SetOps(KeyOpVerify)
	if _, err := NewSignerFromKey(k); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("verify-only key signed: %v", err)
	}
	if _, err := NewVerifierFromKey(k); err != nil {
		t.Fatalf("verify-only key can't verify: %v", err)
	}
	k.SetOps(KeyOpSign, KeyOpVerify)
	s, err := NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	k.SetAlgorithm(AlgES256) // wrong for an Ed25519 key
	if _, err := NewSignerFromKey(k); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("mismatched key alg: %v", err)
	}
	if _, err := NewVerifierFromKey(k); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("mismatched key alg (verifier): %v", err)
	}
	msg, _ := s.Sign([]byte("x"))
	pubKey, _ := k.Public()
	pubKey.SetAlgorithm(AlgEdDSA)
	v, err := NewVerifierFromKey(pubKey)
	if err != nil || v.Verify(msg) != nil {
		t.Fatalf("verify with public COSE_Key: %v", err)
	}
	// No key_ops means everything is permitted.
	if !(&Key{}).Permits(KeyOpDecrypt) {
		t.Fatal("absent key_ops should permit")
	}
}

func TestKeySetLookup(t *testing.T) {
	mk := func(kid string, alg Algorithm, ops ...KeyOp) *Key {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		k, _ := NewKeyFromPublic(priv.Public())
		k.SetID([]byte(kid))
		if alg != 0 {
			k.SetAlgorithm(alg)
		}
		if len(ops) > 0 {
			k.SetOps(ops...)
		}
		return k
	}
	ks := KeySet{mk("a", AlgEdDSA, KeyOpVerify), mk("a", algEd25519Placeholder()), mk("b", 0)}
	enc, err := ks.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKeySet(enc)
	if err != nil || len(got) != 3 {
		t.Fatalf("ParseKeySet = %d, %v", len(got), err)
	}
	if r := got.Lookup([]byte("a"), 0, 0); len(r) != 2 {
		t.Fatalf("kid a: %d keys", len(r))
	}
	if r := got.Lookup([]byte("a"), AlgEdDSA, KeyOpVerify); len(r) != 1 {
		t.Fatalf("kid a, EdDSA, verify: %d keys", len(r))
	}
	if r := got.Lookup(nil, AlgEdDSA, 0); len(r) != 2 {
		t.Fatalf("EdDSA or unset alg: %d keys", len(r))
	}
	if r := got.Lookup([]byte("a"), 0, KeyOpSign); len(r) != 1 {
		t.Fatalf("kid a permitting sign: %d keys (verify-only key must be excluded)", len(r))
	}
	if _, err := ParseKeySet(mustHexBytes(t, "80")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty KeySet: %v", err)
	}
}

// algEd25519Placeholder stands in for the fully-specified Ed25519
// identifier (-19, RFC 9864) until proposal 029 adds the constant.
func algEd25519Placeholder() Algorithm { return Algorithm(-19) }

func TestKeyDeriverSymmetric(t *testing.T) {
	k := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeSymmetric), keyLabelSymK: bytes.Repeat([]byte{1}, 16)}}
	d, err := k.KeyDeriver(AlgA128KW)
	if err != nil || d.Algorithm() != AlgA128KW {
		t.Fatalf("A128KW: %v", err)
	}
	if _, err := k.KeyDeriver(AlgA256KW); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("16-byte key for A256KW: %v", err)
	}
	if d, err := k.KeyDeriver(AlgDirect); err != nil || d.Algorithm() != AlgDirect {
		t.Fatalf("direct: %v", err)
	}
	ec := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeEC2)}}
	if _, err := ec.KeyDeriver(AlgA128KW); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("EC2 KeyDeriver: %v", err)
	}
}

func TestKeyPublicStripsPrivate(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := NewKeyFromSigner(priv)
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	if pub.get(keyLabelD) != nil || k.get(keyLabelD) == nil {
		t.Fatal("Public didn't strip d, or modified the original")
	}
	sym := &Key{params: map[int64]any{keyLabelKty: int64(KeyTypeSymmetric), keyLabelSymK: []byte{1}}}
	if _, err := sym.Public(); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("symmetric Public: %v", err)
	}
}

func TestKeyMarshalInStruct(t *testing.T) {
	// Key implements corecbor.Marshaler, so a struct field encodes the
	// real COSE_Key (v0.2.2 encoded an empty map).
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := NewKeyFromPublic(priv.Public())
	type wrapper struct {
		K *Key `cbor:"1"`
	}
	b, err := corecbor.Marshal(wrapper{K: k})
	if err != nil {
		t.Fatal(err)
	}
	var w wrapper
	if err := corecbor.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	if w.K == nil || !bytes.Equal(w.K.get(keyLabelX).([]byte), k.get(keyLabelX).([]byte)) {
		t.Fatal("Key did not round-trip through Marshal/Unmarshal")
	}
}
