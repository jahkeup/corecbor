// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cose

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor"
)

// RFC 9338 Appendix A keys (the cose-wg example keys).
func rfc9338Keys(t testing.TB) (p256, p521 *ecdsa.PublicKey, ed ed25519.PublicKey) {
	t.Helper()
	pt := func(c elliptic.Curve, x, y string) *ecdsa.PublicKey {
		pub, err := ecdsa.ParseUncompressedPublicKey(c, append(append([]byte{4}, hx(t, x)...), hx(t, y)...))
		if err != nil {
			t.Fatal(err)
		}
		return pub
	}
	p256 = pt(elliptic.P256(),
		"bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
		"20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e")
	p521 = pt(elliptic.P521(),
		"0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8f42ad",
		"01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1d9475")
	ed = ed25519.PublicKey(hx(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
	return p256, p521, ed
}

var (
	cA, cB  = corecbor.MakeArray, corecbor.Bytes
	content = []byte("This is the content.")
)

func cMap(kv ...any) corecbor.Value {
	var es []corecbor.MapEntry
	for i := 0; i < len(kv); i += 2 {
		v, ok := kv[i+1].(corecbor.Value)
		if !ok {
			v = goToCBOR(kv[i+1])
		}
		es = append(es, corecbor.MapEntry{Key: goToCBOR(kv[i]), Value: v})
	}
	return corecbor.MakeMapFromSlice(es)
}

// rfc9338CS builds a COSE_Countersignature [protected, {kid}, signature].
func rfc9338CS(t testing.TB, prot, kid, sig string) corecbor.Value {
	return cA(cB(hx(t, prot)), cMap(int64(4), []byte(kid)), cB(hx(t, sig)))
}

type rfc9338Vector struct {
	name   string
	size   int
	msg    corecbor.Value
	key    any
	decode func([]byte) (CountersignTarget, error)
}

// rfc9338Vectors are the RFC 9338 Appendix A messages and the key that
// verifies each countersignature.
func rfc9338Vectors(t testing.TB) []rfc9338Vector {
	p256, p521, ed := rfc9338Keys(t)
	return []rfc9338Vector{
		{
			"A.1.1 COSE_Sign", 180,
			corecbor.MakeTag(98, cA(cB(nil),
				cMap(int64(11), rfc9338CS(t, "a10126", "11", "5ac05e289d5d0e1b0a7f048a5d2b643813ded50bc9e49220f4f7278f85f19d4a77d655c9d3b51e805a74b099e1e085aacd97fc29d72f887e8802bb6650cceb2c")),
				cB(content),
				cA(cA(cB(hx(t, "a10126")), cMap(int64(4), []byte("11")), cB(hx(t, "e2aeafd40d69d19dfe6e52077c5d7ff4e408282cbefb5d06cbf414af2e19d982ac45ac98b8544c908b4507de1e90b717c3d34816fe926a2b98f53afd2fa0f30a")))))),
			p256,
			func(b []byte) (CountersignTarget, error) { return UnmarshalSign(b) },
		},
		{
			"A.2.1 COSE_Sign1", 275,
			corecbor.MakeTag(18, cA(cB(hx(t, "a201260300")),
				cMap(int64(4), []byte("11"), int64(11), rfc9338CS(t, "a1013823", "bilbo.baggins@hobbiton.example", "01b1291b0e60a79c459a4a9184a0d393e034b34af069a1cca34f5a913affff698002295fa9f8fcbfb6fdff59132fc0c406e98754a98f1fbfe81c03095f481856bc470170227206fa5bee3c0431c56a66824e7aaf692985952e31271434b2ba2e47a335c658b5e995aeb5d63cf2d0ced367d3e4cc8fffd53b70d115baa9e86961fbd1a5cf")),
				cB(content),
				cB(hx(t, "bb587d6b15f47bfd54d2cbfcecef75451e92b08a514bd439fa3aa65c6ac92df0d7328c4a47529b32add3dd1b4e940071c021e9a8f2641f1d8e3b053ddd65ae52")))),
			p521,
			func(b []byte) (CountersignTarget, error) { return UnmarshalSign1(b) },
		},
		{
			"A.3.1 COSE_Encrypt", 326,
			corecbor.MakeTag(96, cA(cB(hx(t, "a10101")),
				cMap(int64(5), hx(t, "c9cf4df2fe6c632bf7886413"), int64(11), rfc9338CS(t, "a1013823", "bilbo.baggins@hobbiton.example", "00929663c8789bb28177ae28467e66377da12302d7f9594d2999afa5dfa531294f8896f2b6cdf1740014f4c7f1a358e3a6cf57f4ed6fb02fcf8f7aa989f5dfd07f0700a3a7d8f3c604ba70fa9411bd10c2591b483e1d2c31de003183e434d8fba18f17a4c7e3dfa003ac1cf3d30d44d2533c4989d3ac38c38b71481cc3430c9d65e7ddff")),
				cB(hx(t, "7adbe2709ca818fb415f1e5df66f4e1a51053ba6d65a1a0c52a357da7a644b8070a151b0")),
				cA(cA(cB(hx(t, "a1013818")),
					cMap(int64(-1), cMap(int64(1), int64(2), int64(-1), int64(1),
						int64(-2), hx(t, "98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91d6280"),
						int64(-3), true),
						int64(4), []byte("meriadoc.brandybuck@buckland.example")),
					cB(nil))))),
			p521,
			func(b []byte) (CountersignTarget, error) { return UnmarshalEncrypt(b) },
		},
		{
			"A.4.1 COSE_Encrypt0", 136,
			corecbor.MakeTag(16, cA(cB(hx(t, "a10101")),
				cMap(int64(5), hx(t, "02d1f7e6f26c43d4868d87ce"), int64(11), rfc9338CS(t, "a10127", "11", "e10439154cc75c7a3a5391491f88651e0292fd0fe0e02cf740547eaf6677b4a4040b8eca16db592881262f77b14c1a086c02268b17171ca16be4b8595f8c0a08")),
				cB(hx(t, "60973a94bb2898009ee52ecfd9ab1dd25867374b162e2c03568b41f57c3cc16f9166250a")))),
			ed,
			func(b []byte) (CountersignTarget, error) { return UnmarshalEncrypt0(b) },
		},
		{
			"A.5.1 COSE_Mac", 159,
			corecbor.MakeTag(97, cA(cB(hx(t, "a10105")),
				cMap(int64(11), rfc9338CS(t, "a10127", "11", "602566f4a311dc860740d2df54d4864555e85bc036ea5a6cf7905b96e499c5f66b01c4997f6a20c37c37543adea1d705347d38a5b13594b29583dd741f455101")),
				cB(content),
				cB(hx(t, "2bdcc89f058216b8a208ddc6d8b54aa91f48bd63484986565105c9ad5a6682f6")),
				cA(cA(cB(nil), cMap(int64(1), int64(-6), int64(4), []byte("our-secret")), cB(nil))))),
			ed,
			func(b []byte) (CountersignTarget, error) { return UnmarshalMac(b) },
		},
		{
			// RFC 9338 A.6.1 repeats A.5.1's size (159); the message as
			// given encodes to 139 bytes.
			"A.6.1 COSE_Mac0", 139,
			corecbor.MakeTag(17, cA(cB(hx(t, "a10105")),
				cMap(int64(11), rfc9338CS(t, "a10127", "11", "968a315df6b4f26362e11f4cfd2f2f4e76232f39657bf1598837ff9332cddd7581e248116549451f81ef823da5974f885b681d3d6e38fc4142d8f8e9e7dc8f0d")),
				cB(content),
				cB(hx(t, "a1a848d3471f9d61ee49018d244c824772f223ad4f935293f1789fc3a08d8c58")))),
			ed,
			func(b []byte) (CountersignTarget, error) { return UnmarshalMac0(b) },
		},
	}
}

// TestRFC9338Vectors verifies the countersignatures of RFC 9338
// Appendix A, checking each message's size against the RFC.
func TestRFC9338Vectors(t *testing.T) {
	for _, c := range rfc9338Vectors(t) {
		t.Run(c.name, func(t *testing.T) {
			data := encodeCBOR(t, c.msg)
			if len(data) != c.size {
				t.Fatalf("encoded size %d, RFC says %d", len(data), c.size)
			}
			target, err := c.decode(data)
			if err != nil {
				t.Fatal(err)
			}
			css, err := Countersignatures(target)
			if err != nil || len(css) != 1 {
				t.Fatalf("Countersignatures = %d, %v", len(css), err)
			}
			v, err := NewVerifier(c.key)
			if err != nil {
				t.Fatal(err)
			}
			if err := v.VerifyCountersignature(target, css[0]); err != nil {
				t.Fatalf("VerifyCountersignature: %v", err)
			}
			// A flipped signature byte fails.
			bad := css[0]
			bad.Signature = bytes.Clone(bad.Signature)
			bad.Signature[len(bad.Signature)-1] ^= 1
			if err := v.VerifyCountersignature(target, bad); !errors.Is(err, ErrVerification) {
				t.Fatalf("tampered: err = %v, want ErrVerification", err)
			}
		})
	}
}

// TestCountersignRoundTrip signs full and abbreviated countersignatures
// on every target type and verifies them after a Marshal/Unmarshal round
// trip.
func TestCountersignRoundTrip(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cs1, _ := NewSigner(ec)
	cs2, _ := NewSigner(hardEdPriv)
	v1, _ := NewVerifier(&ec.PublicKey)
	v2, _ := NewVerifier(hardEdPub)

	s, _ := NewSigner(hardEdPriv)
	sign1, _ := s.Sign(content)
	sign, _ := SignMulti(content, []*Signer{s})
	macKey := bytes.Repeat([]byte{0x0b}, 32)
	mac0, _ := ComputeMAC0(content, macKey, AlgHMAC256)
	mac, _ := ComputeMACMulti(content, macKey, AlgHMAC256, []KeyDeriver{&AESKWKey{Key: bytes.Repeat([]byte{1}, 16)}})
	aesKey := bytes.Repeat([]byte{0x0d}, 16)
	enc0, _ := Encrypt0Seal(content, aesKey, AlgA128GCM)
	enc, _ := EncryptMulti(content, AlgA128GCM, []KeyDeriver{&AESKWKey{Key: bytes.Repeat([]byte{2}, 16)}})

	type rt struct {
		target CountersignTarget
		again  func(CountersignTarget) (CountersignTarget, error)
	}
	for name, c := range map[string]rt{
		"Sign1": {sign1, func(m CountersignTarget) (CountersignTarget, error) {
			b, err := MarshalSign1(m.(*Sign1))
			if err != nil {
				return nil, err
			}
			return UnmarshalSign1(b)
		}},
		"Sign": {sign, func(m CountersignTarget) (CountersignTarget, error) {
			b, err := MarshalSign(m.(*Sign))
			if err != nil {
				return nil, err
			}
			return UnmarshalSign(b)
		}},
		"Mac0": {mac0, func(m CountersignTarget) (CountersignTarget, error) {
			b, err := MarshalMac0(m.(*Mac0))
			if err != nil {
				return nil, err
			}
			return UnmarshalMac0(b)
		}},
		"Mac": {mac, func(m CountersignTarget) (CountersignTarget, error) {
			b, err := MarshalMac(m.(*Mac))
			if err != nil {
				return nil, err
			}
			return UnmarshalMac(b)
		}},
		"Encrypt0": {enc0, func(m CountersignTarget) (CountersignTarget, error) {
			b, err := MarshalEncrypt0(m.(*Encrypt0))
			if err != nil {
				return nil, err
			}
			return UnmarshalEncrypt0(b)
		}},
		"Encrypt": {enc, func(m CountersignTarget) (CountersignTarget, error) {
			b, err := MarshalEncrypt(m.(*Encrypt))
			if err != nil {
				return nil, err
			}
			return UnmarshalEncrypt(b)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := cs1.Countersign(c.target); err != nil {
				t.Fatal(err)
			}
			if err := cs2.Countersign(c.target); err != nil {
				t.Fatal(err)
			}
			if err := cs2.Countersign0(c.target); err != nil {
				t.Fatal(err)
			}
			if err := cs2.Countersign0(c.target); err == nil {
				t.Fatal("second Countersign0 succeeded")
			}
			got, err := c.again(c.target)
			if err != nil {
				t.Fatal(err)
			}
			css, err := Countersignatures(got)
			if err != nil || len(css) != 2 {
				t.Fatalf("Countersignatures = %d, %v", len(css), err)
			}
			if err := v1.VerifyCountersignature(got, css[0]); err != nil {
				t.Fatalf("first: %v", err)
			}
			if err := v2.VerifyCountersignature(got, css[1]); err != nil {
				t.Fatalf("second: %v", err)
			}
			if err := v1.VerifyCountersignature(got, css[1]); err == nil {
				t.Fatal("second countersignature verified with the first key")
			}
			if err := v2.VerifyCountersignature0(got); err != nil {
				t.Fatalf("abbreviated: %v", err)
			}
			if err := v1.VerifyCountersignature0(got); err == nil {
				t.Fatal("abbreviated countersignature verified with the wrong key")
			}
			// The countersignatures don't disturb the target's own
			// verification.
			switch m := got.(type) {
			case *Sign1:
				if err := v2.Verify(m); err != nil {
					t.Fatal(err)
				}
			case *Mac0:
				if err := VerifyMAC0(m, macKey, AlgHMAC256); err != nil {
					t.Fatal(err)
				}
			case *Encrypt0:
				if _, err := Encrypt0Open(m, aesKey); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

// TestCountersignChecks covers the error paths.
func TestCountersignChecks(t *testing.T) {
	cs, _ := NewSigner(hardEdPriv)
	v, _ := NewVerifier(hardEdPub)

	// The target must be finished, with its payload attached.
	if err := cs.Countersign(&Sign1{Payload: content}); !errors.Is(err, ErrInvalidKey) && !errors.Is(err, ErrMalformed) {
		t.Fatalf("unsigned Sign1: err = %v", err)
	}
	s, _ := NewSigner(hardEdPriv)
	det, _ := s.SignDetached(content)
	if err := cs.Countersign(det); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("detached: err = %v, want ErrMissingPayload", err)
	}

	m, _ := s.Sign(content)
	if css, err := Countersignatures(m); err != nil || len(css) != 0 {
		t.Fatalf("no countersignatures: %d, %v", len(css), err)
	}
	if err := v.VerifyCountersignature0(m); !errors.Is(err, ErrVerification) {
		t.Fatalf("no abbreviated countersignature: err = %v, want ErrVerification", err)
	}

	// Countersignatures belong in the unprotected bucket.
	bad := &Sign1{Payload: content, Signature: m.Signature}
	_ = bad.Protected.SetChecked(HeaderCountersignature, corecbor.MakeArray(cB(nil), corecbor.MakeMap(), cB(nil)))
	if _, err := Countersignatures(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("protected label 11: err = %v, want ErrMalformed", err)
	}
	// Malformed label 11 values.
	for _, val := range []corecbor.Value{
		corecbor.Uint(1),
		cA(),
		cA(cB(nil), corecbor.MakeMap()),
		cA(cA(cB(nil), corecbor.MakeMap(), cB(nil)), corecbor.Uint(1)),
	} {
		mm := &Sign1{Payload: content, Signature: m.Signature}
		_ = mm.Unprotected.SetChecked(HeaderCountersignature, val)
		if _, err := Countersignatures(mm); !errors.Is(err, ErrMalformed) {
			t.Fatalf("label 11 = %v: err = %v, want ErrMalformed", val, err)
		}
	}

	// crit can only list protected labels (RFC 9052 §3.1) and
	// countersignatures are unprotected (RFC 9338 §2), so a crit
	// listing 11 stays unsatisfiable: Verify rejects it, and the
	// countersignature verifier rejects the protected label 11 that
	// would satisfy it.
	critMsg := signedWith(t, content, map[int64]any{2: []any{int64(11)}, 11: []byte{0}})
	if err := v.Verify(critMsg); !errors.Is(err, ErrCriticalHeader) {
		t.Fatalf("Verify, crit [11]: err = %v, want ErrCriticalHeader", err)
	}
	if err := cs.Countersign(critMsg); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Countersign, protected label 11: err = %v, want ErrMalformed", err)
	}
	if err := v.VerifyCountersignature0(critMsg); !errors.Is(err, ErrMalformed) {
		t.Fatalf("VerifyCountersignature0, protected label 11: err = %v, want ErrMalformed", err)
	}
}
