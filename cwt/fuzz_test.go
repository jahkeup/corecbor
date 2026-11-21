// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package cwt_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/jahkeup/corecbor/cose"
	"github.com/jahkeup/corecbor/cwt"
)

func fuzzSeeds(f *testing.F) {
	for _, s := range []string{
		"a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b7703" +
			"7818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0" +
			"051a5610d9f0061a5610d9f007420b71",
		"a1410101", "a1810101", "a13bfffffffffffffffe6161", "a2041a6553f100041a00000001",
		"a1041bffffffffffffffff", "a104f97e00", "a103826161626262", "a108a102420102",
		"a108a10343010203", "a4096a72656164207772697465182602182741011828190e10",
		"d90259a1016161", "d83dd28440a0f640", "80", "ff", "",
	} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
}

// FuzzDecodeClaimsSet: arbitrary bytes return a typed error or a claims
// set that re-encodes, and never panic.
func FuzzDecodeClaimsSet(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, opts := range []cwt.DecodeOptions{{}, {AllowDuplicateClaims: true, RejectUnknownCnf: true}} {
			cs, err := cwt.DecodeClaimsSetWith(data, opts)
			if err != nil {
				continue
			}
			// A decoded set must re-encode to bytes that decode again.
			// (Byte stability isn't required: a float NumericDate passes
			// through time.Time's nanoseconds, which a float64 epoch can't
			// always represent exactly — the same as v0.2.2.)
			out, err := cs.Encode()
			if err != nil {
				continue // e.g. a cnf key the encoder reduces differently
			}
			cs2, err := cwt.DecodeClaimsSet(out)
			if err != nil {
				t.Fatalf("re-decode of %x: %v", out, err)
			}
			if cs2.Issuer != cs.Issuer || !bytes.Equal(cs2.CWTID, cs.CWTID) || len(cs2.PrivateClaims) != len(cs.PrivateClaims) {
				t.Fatalf("round trip changed claims: %+v vs %+v", cs, cs2)
			}
		}
		_, _ = cwt.DecodeUCCS(data)
		var h cose.Headers
		_, _, _ = cwt.ClaimsFromHeaders(&h)
	})
}

// FuzzVerify: arbitrary envelope bytes through every verify entry point
// with fixed keys never panic.
func FuzzVerify(f *testing.F) {
	fuzzSeeds(f)
	signed, _ := cwt.Sign(&cwt.ClaimsSet{Issuer: "a", Expiration: t0}, mustSigner())
	f.Add(signed)
	f.Add(append([]byte{0xd8, 0x3d}, signed...))
	k, _ := cose.NewKeyFromPublic(edPub)
	resolver := cose.KeySetResolver(cose.KeySet{k})
	verifier, _ := cose.NewVerifier(edPub)
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx := context.Background()
		_, _ = cwt.Verify(data, verifier)
		_, _ = cwt.VerifyMAC(data, macKey, cose.AlgHMAC256)
		_, _ = cwt.Decrypt(data, aesKey, nonce, cose.AlgA128GCM)
		_, _ = cwt.VerifyToken(ctx, data, cwt.VerifyOptions{Keys: resolver})
		_, _ = cwt.VerifyMACToken(ctx, data, macKey, cwt.VerifyOptions{})
		_, _ = cwt.OpenToken(ctx, data, aesKey, cwt.VerifyOptions{})
		if msg, err := cose.UnmarshalSign1(data); err == nil {
			_, _, _ = cwt.ClaimsFromHeaders(&msg.Protected)
			_, _, _ = cwt.ClaimsFromHeaders(&msg.Unprotected)
		}
	})
}

func mustSigner() *cose.Signer {
	s, err := cose.NewSigner(edPriv)
	if err != nil {
		panic(err)
	}
	return s
}
