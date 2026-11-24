# 027 — COSE verification hardening

## Header

| Field | Value |
|---|---|
| **Number** | 027 |
| **Tier** | 3 |
| **Status** | Closed |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 002 (COSE), 011 (multi-signer), 021 (core codec safety), 022 (raw-byte preservation), 034 (compatibility policy) |
| **Supersedes** | none (amends 002 acceptance criteria that were marked met but are not implemented) |
| **Spec sections touched** | none in `encoder-decoder-spec.md`; cose module contract only |

---

## TL;DR

The `cose` module verifies signatures, MACs and AEAD tags over bytes it
*re-creates* rather than the bytes on the wire. It takes the algorithm from
the key rather than the message, ignores `crit`, fails open in
`VerifyMulti`, and panics on some malformed headers. This proposal makes
every verify, decrypt and unmarshal path **fail closed**:

- verify over the original protected-header bytes;
- bind the header `alg` to the key and to a caller allow-list;
- process `crit`;
- reject duplicate and cross-bucket labels;
- bound decode work (opt-in tighter limits through new `Unmarshal*With`);
- never panic on untrusted input.

No exported identifier changes signature; three functions gain an
appended `...Option` parameter whose no-option behavior is unchanged
apart from listed Safety defects.

Acceptance: every finding below has a regression test, plus three new fuzz
targets that run clean for 60s in CI.

Velocity note: H1 (raw protected bytes) does not need 022, because the
protected bucket is already a bstr (see Behavior item 1); only the
whole-message raw-span API waits on 022. All items can ship
independently, in the phase order below.

Compatibility: fail-closed checks that RFC 9052 requires are
Contract defects under proposal 034 (the module documents RFC 9052).
Each has a named, deprecated legacy selector, and none is included in
any `CompatV02` bundle, because they weaken verification. Fail-open and
resource-exhaustion paths are Safety defects with no selector beyond an
explicit opt-out. See Compatibility selection.

---

## Motivation

Every finding was confirmed by reading the code at the cited line. The ones
marked **(probe)** were also reproduced with a throwaway test on
2026-11-20.

### H1. Protected headers are re-encoded before verify/decrypt **(probe)**

`decodeProtected` (`cose/headers.go:134-156`) parses the protected `bstr`
into `map[any]any` and discards the original bytes. Each verifier then calls
`encodeProtected()`, which re-serializes the map with the shared
CoreDeterministic encoder (`headers.go:88-131`). The affected call sites:

| Path | Location |
|---|---|
| `Verifier.Verify` | `sign.go:145` |
| `VerifyMAC0` | `mac.go:74` |
| `DecryptEncrypt0` | `encrypt.go:70` |
| `VerifyMulti` | `sign_multi.go:43,51` |
| `VerifyMACMulti` | `mac_multi.go:100` |
| `DecryptMulti` | `encrypt_multi.go:134` |

RFC 9052 §4.4 says the `body_protected` in Sig_structure is the bstr *as
transmitted*. Any sender whose map order, integer width or label set differs
from our re-encoding fails verification. The probe signed
`{4: h'01', 1: -7}` (valid CBOR, keys not in bytewise order), and
`Verifier.Verify` returned `ErrVerification`.

Consumers that hit this include anything that verifies messages produced
elsewhere: mDL readers, SCITT transparency services, C2PA validators, and
verifiers of WebAuthn-adjacent COSE objects.

### H2. The header `alg` is never checked

- `Verifier.verifyBytes` switches on `v.alg`, which is derived from the
  public key type in `algForPublicKey` (`sign.go:127,159,222-240`).
  `msg.Protected.Algorithm()` is never read. A message with no `alg`, an
  `alg` only in the unprotected bucket, or `alg: ES384` verified with a
  P-256 key all reach the P-256/SHA-256 path.
- `VerifyMAC0` takes `alg` from the caller and ignores the header
  (`mac.go:63-90`).
- `VerifyMACMulti` takes `alg` **from the attacker-controlled protected
  header** (`mac_multi.go:86`) with no allow-list. A forger can relabel a
  message `HMAC 256/64` (alg 4), so only an 8-byte tag needs to match
  (`mac_multi.go:113-115`). That is a truncation downgrade.
- `DecryptMulti` likewise takes the content `alg` from the header
  (`encrypt_multi.go:102`). The impact is lower because every supported
  AEAD is authenticated, but it should share the same policy hook.

Today the confusion is mostly latent, because one curve maps to one alg.
It becomes exploitable as soon as 029 adds RSA (RS256 vs PS256), the
fully-specified identifiers (`ESP256` vs `ES256`), or ML-DSA.

### H3. `crit` is ignored

`headerLabelCritical` is declared (`headers.go:13`) but never read.
RFC 9052 §3.1 says a recipient MUST reject a message whose `crit` lists a
label it does not understand. Proposal 002 specified `ErrCriticalHeader`
(002:537), but `cose/errors.go:8-15` does not define it.

### H4. Duplicate labels are not rejected

- Within a bucket: `decodeProtected` and `decodeUnprotected` use
  `corecbor.NewDecoder()` without `RejectDuplicateMapKeys()`
  (`headers.go:138`, `marshal.go:57` and siblings), so the last duplicate
  wins silently.
- Across buckets: RFC 9052 §3 says a label MUST NOT occur in both protected
  and unprotected, and nothing checks this. An attacker can add an
  unprotected `kid` that shadows nothing today but will shadow it once 028
  adds bucket-merged accessors.

### H5. Unmarshal panics on untrusted input **(probe)**

`cborToGo` returns `[]byte` for a bstr key and `corecbor.Value` for
array/map keys (`headers.go:211-227`). Using either as a Go map key panics
(`headers.go:152,174`). The probe input
`18([h'', {h'01': 1}, null, h''])` crashed `UnmarshalSign1` with
`hash of unhashable type []uint8`. COSE labels are `int / tstr` only
(RFC 9052 §3), so these inputs must be rejected with `ErrMalformed`.

Other panics and nil dereferences:

- `derToRawECDSA` (`sign.go:259-271`) computes `size-len(R)`. If a KMS or
  HSM returns DER whose R or S is longer than the curve size (bad DER, or a
  leading-zero-padded integer), the slice index goes negative and it
  panics. It also ignores trailing ASN.1 bytes (the `rest` return of
  `asn1.Unmarshal` is discarded).
- `hashData` panics on an unknown hash (`sign.go:254`). It is unreachable
  today, but 029 adds algorithms.
- `ECDHESKey.WrapKey` and `DeriveKey` dereference a nil `PeerPublic`
  (`ecdh_deriver.go:29,101`). `UnwrapKey` dereferences a nil `PrivateKey`
  (`ecdh_deriver.go:72`).

### H6. `VerifyMulti` fails open **(probe)**

`VerifyMulti` returns `(nil, nil)` when no signature verifies
(`sign_multi.go:38-67`). Malformed signatures are skipped with `continue`.
The probe verified a COSE_Sign with an unrelated key and got
`idx=[] err=<nil>`. A caller that checks only `err` accepts the message.

### H7. Missing external AAD on multi-recipient verify and decrypt

`ComputeMACMulti` and `EncryptMulti` honor `WithMACExternalAAD` and
`WithEncryptExternalAAD` (`mac_multi.go:50`, `encrypt_multi.go:41`). The
matching `VerifyMACMulti` and `DecryptMulti` hard-code `nil`
(`mac_multi.go:105`, `encrypt_multi.go:139`) and take no options. Any
message built with external AAD can never be verified or decrypted.

### H8. Unbounded PBES2 work factor

`PBES2Key.UnwrapKey` reads the iteration count from the recipient header
(`pbes2_deriver.go:66-75`) and passes it straight to `pbkdf2.Key`. An
attacker can send `count = 2^31` and pin a CPU per message. Zero and
negative counts are not rejected in `cose`; whether they error depends on
`crypto/pbkdf2` internals. The count label `-21` also collides with the
registered RFC 9053 `PartyU identity` parameter (IANA COSE Header Algorithm
Parameters). 029 covers the identifier fix.

### H9. Header values that can't be encoded become CBOR `null` **(probe)**

`goToCBOR` (`headers.go:180-208`) encodes any unrecognized Go type as
`null`. That includes the package's own `Algorithm` type, so
`h.Set(int64(1), AlgES256)` produced `a101f6` (`{1: null}`) in the probe.
The `int32`, `uint8` and `[]any` types are dropped the same way.

On decode, `cborToGo` converts uint values ≥ 2^63 to negative `int64`
(`headers.go:214`), and negint values below −2^63 wrap (`headers.go:216`).

### H10. Concurrency contract is undefined and partly unsafe

- `Signer.enc` and `Verifier.enc` are `corecbor.New` encoders
  (`sign.go:43,134`), which are documented as not goroutine-safe
  (`encoder.go:50`). Sig_structure contains no maps, so the sort cache is
  not touched today. The hazard is latent, but nothing in the type contract
  protects it.
- `Headers.encodeProtected` writes `encodedCache` and `cacheValid` during
  Verify (`headers.go:99-100`). Verifying the same `*Sign1` from two
  goroutines is a data race.
- `UnmarshalSign1` copies `Headers` by value (`marshal.go:122-123`), so the
  copies share `params`. A `Set` through one copy leaves another copy's
  cache stale. Any later Marshal or Verify then signs or verifies the wrong
  bytes.

### H11. A nil payload means "detached" and "empty" at once

`encodeSigStructure` turns a nil payload into an empty bstr
(`sign.go:207-209`). Because `UnmarshalSign1` maps a CBOR `null` payload to
nil (`marshal.go:107-108`), a detached message verified without supplying
the payload is checked against `h''`. A message signed over the empty
payload therefore verifies when the caller forgot to attach content.
Proposal 002 specified `ErrMissingPayload` (002:535), and it was never
added.

### H12. The fuzz target from the 002 acceptance criteria is missing

Proposal 002 lists `FuzzUnmarshalNeverPanics` as gating (002:560,606).
The cose module has no fuzz files, which is how H5 went unnoticed.

### H13. Error chains are flattened

`fmt.Errorf("%w: %v", ErrMalformed, err)` (`marshal.go:60,95,100` and
siblings) hides the underlying corecbor sentinel (`ErrTruncated`,
`ErrMemoryBudgetExceeded`, `ErrDuplicateMapKey`) from `errors.Is`.

---

## Proposal

### Public API surface

```go
// errors.go — new sentinels (each wraps nothing; discriminate via errors.Is).
var (
	ErrCriticalHeader     = errors.New("cose: unprocessed critical header parameter")
	ErrMissingPayload     = errors.New("cose: payload is detached and none was supplied")
	ErrAlgorithmMismatch  = errors.New("cose: header algorithm does not match key or policy")
	ErrDuplicateLabel     = errors.New("cose: header label present more than once")
	ErrUnsupportedHeader  = errors.New("cose: header value type not encodable")
)

// Headers keeps the wire bytes it was decoded from. Raw returns them
// (nil for locally-constructed headers). Verify/Decrypt paths use Raw()
// when non-nil and never re-encode.
func (h *Headers) Raw() []byte

// Set keeps its v0.2.2 signature (no result). It now encodes every
// type SetChecked accepts, so Set(1, AlgES256) stores alg -7 instead of
// null. A value it still can't encode is recorded, and the next
// Marshal* of a message carrying these headers returns
// ErrUnsupportedHeader instead of silently emitting null.
// Set invalidates Raw().
//
// Deprecated: use SetChecked, which reports the error at the call site.
func (h *Headers) Set(label, value any)

// SetChecked validates and sets a header parameter. Accepted value
// types: int64, int, uint64, Algorithm, string, []byte, bool,
// corecbor.Value. Labels: int64, int, string. It invalidates Raw().
func (h *Headers) SetChecked(label, value any) error

// ---- verification policy (shared by Sign1, Sign, Mac0, Mac, Encrypt0, Encrypt)

// WithAllowedAlgorithms restricts the header alg to the given set. When
// unset, the default is exactly the algorithm(s) implied by the key.
func WithAllowedAlgorithms(algs ...Algorithm) VerifierOption

// WithKnownCriticalHeaders declares labels (beyond the RFC 9052 §3.1 set
// this package itself processes) that the caller will process. Any other
// label in crit → ErrCriticalHeader.
func WithKnownCriticalHeaders(labels ...any) VerifierOption

// DecodeLimits bounds Unmarshal*With work. The zero value applies the
// same limits as the existing Unmarshal* functions (the core decoder
// defaults), so DecodeLimits{} changes nothing.
type DecodeLimits struct {
	MemoryBudget int // 0 → core default (none)
	MaxDepth     int // 0 → core default (256)
	// Deprecated: duplicate labels violate RFC 9052 §3; removed no
	// earlier than v0.5.0.
	AllowDuplicateLabels bool
}

// RecommendedDecodeLimits is the recommended bound for untrusted
// input: 1 MiB budget, depth 16.
var RecommendedDecodeLimits = DecodeLimits{MemoryBudget: 1 << 20, MaxDepth: 16}

func UnmarshalSign1With(data []byte, lim DecodeLimits) (*Sign1, error) // + siblings

// VerifyDetached is the explicit detached-payload entry point; Verify on a
// message with nil Payload returns ErrMissingPayload.
func (v *Verifier) VerifyDetached(msg *Sign1, payload []byte) error

// ---- multi-party

type VerifyPolicy int

const (
	RequireAny VerifyPolicy = iota // ≥1 signature verifies (default)
	RequireAll                     // every signature verifies
)

// VerifyMulti returns ErrVerification when the policy is not satisfied.
// The []int result lists verified signature indices. With no policy
// argument it applies RequireAny, which is v0.2.2's acceptance rule
// except that zero verified signatures is now an error (Safety defect:
// v0.2.2 returned ([], nil)).
func VerifyMulti(msg *Sign, verifiers []*Verifier, policy ...VerifyPolicy) ([]int, error)

// VerifyMACMulti / DecryptMulti gain options (external AAD, allowed
// algs). With no options they behave as v0.2.2 (nil external AAD, any
// algorithm the package implements) except that VerifyMACMulti no
// longer accepts the 64-bit truncated HMAC 256/64 unless listed via
// WithMACAlgorithms (Safety defect: attacker-selected tag truncation).
func VerifyMACMulti(msg *Mac, recipient KeyDeriver, recipientIndex int, opts ...MACOption) error
func DecryptMulti(msg *Encrypt, recipient KeyDeriver, recipientIndex int, opts ...EncryptOption) ([]byte, error)
func WithMACAlgorithms(algs ...Algorithm) MACOption
func WithEncryptAlgorithms(algs ...Algorithm) EncryptOption

// ---- PBES2 bound (see 029 for identifier fix)
type PBES2Key struct {
	Password []byte
	Salt     []byte
	Count    int
	MaxCount int // UnwrapKey rejects header count > MaxCount; 0 → 1_000_000
}
```

`Headers.Set` keeps its v0.2.2 signature, per proposal 034. The checked
variant is the new `SetChecked`; `Set` is deprecated in its favor.

### Behavior

1. **Raw protected bytes.** The `Unmarshal*` functions store the protected
   bstr in `Headers.raw` (using 022's raw-span API, or simply the bstr
   value, which is already raw because it is a byte string). All six
   verify/decrypt paths call `h.protectedBytes()`, which returns `raw`
   when set and otherwise encodes once. The encoded cache field is removed.
   `encodeProtected` becomes a pure function with no writes, which fixes
   both H1 and the H10 data race.

   Note: the protected bucket is itself a bstr, so H1 does **not** need
   022. Keeping `arr[0].BytesVal()` (`marshal.go:88`) is enough. 022 is
   needed only for the cleaner "raw span of whole message" API, so H1 can
   move to Phase 1.
2. **Algorithm binding.** Verify reads `alg` from the protected bucket
   only. It returns `ErrAlgorithmMismatch` when `alg` is absent, appears in
   the unprotected bucket, is not in the allow-list, or is incompatible
   with the key (curve, kty, hash). `VerifyMACMulti` and `DecryptMulti`
   accept, with no options, every algorithm they accepted in v0.2.2
   except `HMAC 256/64`, which must be listed explicitly.
3. **`crit`.**
   - The `crit` header must be in the protected bucket.
   - Its value must be a non-empty array of labels.
   - Every listed label must be present in the message.
   - Every listed label must be understood. The understood set is the
     labels this package interprets plus those registered through
     `WithKnownCriticalHeaders`.
4. **Duplicates.** `Unmarshal*` decodes with `RejectDuplicateMapKeys()`.
   Apart from that, the existing `Unmarshal*` functions keep the v0.2.2
   resource limits; the tighter `RecommendedDecodeLimits` apply only
   through `Unmarshal*With`.
   After both buckets are decoded, any label present in both is rejected
   with `ErrDuplicateLabel`.
5. **Label typing.** Labels other than int or tstr cause `ErrMalformed`
   (fixes H5). Ints outside the int64 range cause `ErrMalformed` (fixes
   H9 on decode).
6. **ECDSA DER conversion.**
   - `derToRawECDSA` checks `len(R.Bytes()) <= size` and the same for S.
   - It rejects non-empty `rest`.
   - It returns `ErrInvalidKey` instead of panicking.
   - `hashData` returns an error instead of panicking.
7. **Nil guards.** Every `KeyDeriver` checks its required fields and
   returns `ErrInvalidKey`.
8. **HMAC key length.** An empty key always fails (Safety defect: a MAC
   under an empty key authenticates nothing). Beyond that, existing
   calls accept the key lengths v0.2.2 accepted: RFC 9053 §3.1 says the
   key SHOULD (not MUST) match the hash size. The new
   `WithStrictMACKeyLength() MACOption` enforces key ≥ hash output size
   and is the recommended path.
9. **Error chains.** All `fmt.Errorf("%w: %v", …)` become
   `fmt.Errorf("%w: %w", ErrMalformed, err)`, so both sentinels stay
   visible to `errors.Is`.
10. **Concurrency contract.** Document that `Signer` and `Verifier` are
    safe for concurrent use after construction, and switch them to
    `sharedEncoder` or a stack encoder. Document that `Headers` and the
    message structs are not safe for concurrent mutation but are safe for
    concurrent read-only verification, which becomes true once item 1
    removes the cache write.

### Failure modes

New sentinels are listed above. Existing sentinels may now appear in new
cases:

- `ErrVerification` from `VerifyMulti` when the policy is not satisfied.
- `ErrMalformed` for bstr, array or map labels.
- `ErrMalformed` wrapping `corecbor.ErrDuplicateMapKey` or
  `corecbor.ErrMemoryBudgetExceeded`.

---

### Implementation notes (Phase 1, 2026-11-20)

- **H1 and the empty protected map.** Decoded headers keep the
  protected bstr (`Headers.raw`, exposed as `Headers.Raw()`), and every
  verify/decrypt path uses it. The encoded cache is gone, so
  `encodeProtected` no longer writes and concurrent verification of one
  message is race-free (`TestConcurrentVerify`). One exception, from
  RFC 9052 §3 and §4.4: when the protected map is empty, the
  Sig/MAC/Enc structures use a zero-length bstr even if the sender
  encoded `h'a0'`. cose-wg `sign1-tests/sign-pass-01` depends on this,
  and re-marshaling such a message emits `h''`. `Set` clears `Raw()`.
  Copies of a `Headers` value still share `params`, so a `Set` through
  one copy leaves another copy's `Raw()` stale; that aliasing predates
  this change and stays with H10 in Phase 3.
- **H11 scope.** Applied to every verifier that takes a payload:
  `Verify`, `VerifyMulti`, `VerifyMAC0`, `VerifyMACMulti`. A nil payload
  returns `ErrMissingPayload`; an empty non-nil payload verifies as
  `h''`, and the decoder keeps `h''` non-nil (`TestVerifyEmptyPayload`).
  `Signer.Sign(nil)` still yields `Payload: nil`, which marshals as
  `null` (detached), so verifying that message now needs
  `VerifyDetached(msg, nil)`; `Sign([]byte{})` produces an attached
  empty payload.
- **H6.** `VerifyMulti` returns `ErrVerification` for zero verified
  signatures, for an empty `Signatures` array, and under `RequireAll`
  when any signature fails. More than one policy argument is
  `ErrInvalidKey`.
- **Extra panic found:** `DecryptMulti` passed the message's IV
  straight to `gcm.Open`, which panics on a wrong-size nonce. It now
  returns `ErrDecryption` (`TestDecryptMultiBadIV`). Same class as H5.
- **DER.** `derToRawECDSA` also rejects zero or negative R/S.
- **H8.** Counts are also capped at `math.MaxInt32` so the `int`
  conversion can't wrap on 32-bit platforms.
- **`make fuzz`** now runs each target from its own package directory,
  so sub-module targets (cose) run, and it skips hidden directories.
- **Interop vectors** from cose-wg/Examples (public domain) are embedded
  in `TestCOSEWGExamples`: `eddsa-sig-01`, `sign-pass-01`,
  `sign-pass-02`, `HMac-01`, `aes-gcm-enc-01`.

**Decided 2026-11-20 (maintainers) — H2 rule for Phase 2.** `alg` is
taken from the protected bucket when present. An `alg` that appears
**only** in the unprotected bucket is accepted if, and only if, it
equals the algorithm the verifier key implies (and passes
`WithAllowedAlgorithms` when set); any other unprotected `alg`, or an
`alg` present in both buckets (also an H4 duplicate), is rejected with
`ErrAlgorithmMismatch`. An unprotected `alg` can't steer verification
to a different algorithm this way, so RFC 9052 §3.1's concern (changing
the identifier as an attack vector) doesn't arise, and cose-wg
`sign-pass-01` keeps verifying. A message with no `alg` at all is
verified with the key's algorithm, as today.

**Decided 2026-11-20 (maintainers) — nil payload means detached.**
`Signer.Sign(nil)` producing a detached message, and `Verify` returning
`ErrMissingPayload` for it, is intended (RFC 9052 §2). To detach a real
payload, sign it and set `Payload = nil` before marshaling (028 adds a
`SignDetached` helper); verify with `VerifyDetached(msg, content)`. An
empty non-nil slice is an attached empty payload. Usage is shown in
runnable examples: `ExampleSigner_Sign`, `ExampleVerifier_VerifyDetached`,
`ExampleSigner_Sign_emptyPayload`, `ExampleVerifyMulti`
(`cose/example_payload_test.go`). The migration guide must call out the
nil-vs-empty distinction.

### Implementation notes (Phase 2, 2026-11-20)

- **H2, as decided.** `bindAlg` (`cose/policy.go`) applies to Sign1,
  each COSE_Sign signer layer, Mac0 and Encrypt0. For Mac0 and Encrypt0
  the caller's `alg` argument plays the role of the key's algorithm. Any
  `alg` header present, protected or unprotected-only, must equal that
  algorithm; `alg` in both buckets, a non-integer `alg` (cose-wg
  `sign-fail-04`'s `"unknown"`), or an `alg` outside
  `WithAllowedAlgorithms`/`WithMACAlgorithms`/`WithEncryptAlgorithms`
  is `ErrAlgorithmMismatch`. No `alg` uses the key's algorithm.
- **H2 on multi-recipient bodies.** `VerifyMACMulti` and `DecryptMulti`
  have no key that implies an algorithm, so the content `alg` must be
  in the protected bucket and in the allowed set (`multiAlg`). An
  unprotected-only `alg` there could steer verification, so it is
  rejected. Defaults: HMAC 256/256, 384/384, 512/512 (256/64 only via
  `WithMACAlgorithms`) and AES-GCM 128/192/256.
- **H3.** `checkCrit` runs on every layer that is verified or used for
  decryption: the body, each COSE_Sign signer, and the selected
  recipient. Understood labels are the RFC 9052 labels 1–6 plus those
  declared through `WithKnownCriticalHeaders`,
  `WithMACKnownCriticalHeaders` or `WithEncryptKnownCriticalHeaders`.
  Label 7 (RFC 8152 countersignature) is not processed by this package,
  so a crit listing it fails unless declared. Recipient-layer crit fails
  closed the same way.
- **`VerifyMulti` with policy.** Each verifier's policy applies to the
  body and to the signer layers it tries. A verifier that rejects a
  layer verifies nothing there, and when the result fails the policy
  the error wraps both `ErrVerification` and the policy sentinel
  (`TestRFC9052CritExample`).
- **H4.** Messages and protected header maps decode with
  `RejectDuplicateMapKeys()`, reported as `ErrMalformed` wrapping
  `ErrDuplicateLabel` (and the core `ErrDuplicateMapKey`). Labels are
  also compared after conversion, so `01` and `1801` collide even in
  maps large enough that the core decoder's encoded-byte dedup would
  miss them (024). A label in both buckets of one layer is
  `ErrDuplicateLabel`. The `DecodeLimits.AllowDuplicateLabels` selector
  arrives with `Unmarshal*With` in Phase 3.
- **H7.** `VerifyMACMulti` and `DecryptMulti` now apply
  `WithMACExternalAAD`/`WithEncryptExternalAAD`.
- **HMAC keys.** An empty key is `ErrInvalidKey` in `ComputeMAC0`,
  `VerifyMAC0` and `ComputeMACMulti` (when a key is supplied), and a
  recovered empty key fails `VerifyMACMulti`. `WithStrictMACKeyLength`
  requires a key at least the hash length.
- **Legacy selectors, deprecated with a v0.5.0 floor, never bundled.**
  `WithLegacyAlgorithmFromKey` and `WithLegacyIgnoreCritical` (Verifier),
  plus `WithLegacyMACHeaders` and `WithLegacyEncryptHeaders`, which
  restore v0.2.2 header handling (alg unbound, crit ignored) for the
  MAC and Encrypt paths. They were added because those paths take a
  different option type. `WithLegacyMACHeaders` does not re-enable
  header-selected HMAC 256/64, which is a safety defect.
- **Vectors.** cose-wg/Examples `sign1-tests/sign-fail-01..04,06,07`
  all fail (03 and 04 with `ErrAlgorithmMismatch`) and `sign-pass-01`
  (unprotected-only `alg`) still verifies. RFC 9052 Appendix C.1.3
  (crit `["reserved"]`) fails with `ErrCriticalHeader` until
  `WithKnownCriticalHeaders("reserved")`, then verifies.
- **Golden.** `cose/mac0/empty-key` and
  `cose/mac0/verify-alg-param-mismatch` changed as intended.
- **Fuzz.** New `FuzzVerifyNeverPanics` drives every
  Unmarshal-then-verify path with policy options; it and the three
  Phase 1 targets ran 60 s each clean.

### Implementation notes (Phase 3, 2026-11-20)

- **H9.** `Set` keeps its v0.2.2 signature and is deprecated in favor of
  `SetChecked`. Both normalize integer labels to `int64`, and `Get`
  normalizes too, so `Get(1)` and `Get(int64(1))` find the same label
  (v0.2.2 treated them as different keys). `SetChecked` also accepts
  `[]any` of the listed types, so a crit array can be set directly. An
  unencodable label or value stored with `Set` makes the next `Marshal*`
  (or protected encoding) return `ErrUnsupportedHeader`. On decode,
  integers outside the int64 range stay `corecbor.Value` instead of
  wrapping (v0.2.2 read 2^64-1 as -1).
- **H10.** `Set`/`SetChecked` write to a copy of the parameter map, so a
  struct copy of `Headers` (which shares the old map) keeps its
  parameters and `Raw()` consistent (`TestHeadersCopyIndependent`).
  `Signer`/`Verifier` use the package's shared encoder;
  `TestConcurrentSignVerify` covers concurrent signing and concurrent
  verification of one message under `-race`.
- **H13.** Every wrapped cause uses `%w`; `Error()` text is unchanged.
- **Decode limits.** `Unmarshal{Sign1,Encrypt0,Mac0,Encrypt,Sign,Mac}With`
  take a `DecodeLimits`; `DecodeLimits{}` is identical to the
  `Unmarshal*` functions. `AllowDuplicateLabels` (deprecated) is the H4
  selector. Applies to the message decode and the protected-map decode.
- **Not changed (pre-existing).** Headers decoded with content the
  deterministic encoder refuses (invalid UTF-8 text, non-finite floats)
  verify fine, because verification uses the received bytes, but can't
  be re-encoded after modification. Found by `FuzzHeadersDecode`
  (corpus seed kept). Treating such input as invalid at decode belongs
  with 023/024's strictness work.

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).

**Bundling rule for `cose`.** Legacy selectors that weaken verification
(alg binding, `crit`, duplicate labels) are never included in a
`CompatV02` bundle. A caller must name each one, so the weakening is
visible at the call site and in code review. `cose`'s bundles carry only
interoperability selectors for code points and emission (029).

| Change | Class | Contract restored | Existing identifiers in v0.3 | Selector |
|---|---|---|---|---|
| H1 verify/decrypt over the received protected bytes | Contract defect | RFC 9052 §4.4 / §5.3 / §6.3 (ToBeSigned/AAD use the protected bstr as transmitted) | raw bytes | none |
| H2 header `alg` must be protected and match key + allow-list | Contract defect | RFC 9052 §3.1 (`alg` "MUST be authenticated where the ability to change the algorithm identifier would provide an attack vector") and §4.4 | enforced | `func WithLegacyAlgorithmFromKey() VerifierOption` — Deprecated; v0.2 behavior. Not bundled |
| H3 `crit` processed | Contract defect | RFC 9052 §3.1 (`crit` MUST be understood) | enforced | `func WithLegacyIgnoreCritical() VerifierOption` — Deprecated. Not bundled |
| H4 duplicate labels within and across buckets rejected | Contract defect | RFC 9052 §3 (labels MUST NOT repeat across buckets); RFC 8949 §5.6 | rejected | `DecodeLimits{AllowDuplicateLabels: true}` via `Unmarshal*With` — field Deprecated. Not bundled |
| H5 bstr/array/map labels → `ErrMalformed` | Safety defect (panic) | — | error | none |
| H6 `VerifyMulti` with zero verified signatures → `ErrVerification` | Safety defect (fail-open authentication) | — | `([], ErrVerification)` instead of `([], nil)`; non-empty results unchanged | none |
| H7 external AAD and algorithm options on `VerifyMACMulti`/`DecryptMulti` | Additive (appended `...Option`) | — | no-option calls behave as v0.2.2 except the HMAC 256/64 row below | `WithMACExternalAAD`, `WithEncryptExternalAAD`, `WithMACAlgorithms`, `WithEncryptAlgorithms` |
| `VerifyMACMulti` rejects header-selected HMAC 256/64 unless listed | Safety defect (attacker-selected truncation) | — | rejected by default | `WithMACAlgorithms(AlgHMAC256_64)` |
| H8 PBES2 iteration count bounded (`MaxCount` zero → 1,000,000) | Safety defect (attacker-controlled unbounded work) | — | bounded; counts ≤ 1,000,000 unchanged | `PBES2Key{MaxCount: -1}` disables the bound (documented unsafe for untrusted input) |
| H9 `Headers.Set` stores `Algorithm`, `int`, etc. correctly; unencodable values surface as `ErrUnsupportedHeader` at `Marshal*` | Contract defect | `cose/headers.go:34` ("Set sets a header parameter"; v0.2.2 wrote `null`) | signature unchanged; `Set` deprecated | `SetChecked(label, value any) error` (new, recommended) |
| H10 concurrency contract | Safety defect (race) | — | safe after construction | none |
| H11 nil payload means detached → `ErrMissingPayload` | Contract defect | RFC 9052 §2 (`nil` payload = detached content, supplied separately) | error; decoder keeps `h''` as a non-nil empty slice so empty-payload messages still verify (`TestVerifyEmptyPayload`) | `VerifyDetached(msg, payload)` (new) |
| `Unmarshal*With` + `RecommendedDecodeLimits` | Additive | — | existing `Unmarshal*` keep v0.2.2 limits | n/a |
| HMAC empty key rejected | Safety defect | — | error | none |
| HMAC key ≥ hash length | Additive (opt-in) | — (RFC 9053 §3.1 is a SHOULD) | v0.2.2 lengths accepted | `WithStrictMACKeyLength() MACOption` (recommended) |
| H13 error chains keep both sentinels | Additive | — | `Error()` text unchanged where it was a single `%w` | n/a |

`cose.CompatV02*` bundles: nothing from 027 (see the bundling rule).

**Appended `...Option` parameters (apidiff-visible, migration-guide
entries):** `VerifyMulti(msg, verifiers, policy ...VerifyPolicy)`,
`VerifyMACMulti(msg, recipient, idx, opts ...MACOption)`,
`DecryptMulti(msg, recipient, idx, opts ...EncryptOption)`.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| Sign1 with non-canonically-ordered protected map from a foreign encoder verifies | `TestVerifyForeignProtectedOrder` (vector from the 2026-11-20 probe) | Yes |
| Same for Mac0, Encrypt0, Sign, Mac, Encrypt | table test over all six | Yes |
| Missing / unprotected / disallowed / key-incompatible `alg` → `ErrAlgorithmMismatch` | `TestAlgBinding*` | Yes |
| `VerifyMACMulti` with header relabelled to alg 4 and 8-byte tag → error | `TestMACMultiTruncationDowngrade` | Yes |
| Unknown label in `crit` → `ErrCriticalHeader`; `crit` in unprotected → `ErrMalformed` | `TestCrit*` | Yes |
| Duplicate label within bucket and across buckets rejected | `TestDuplicateLabel*` | Yes |
| `18([h'', {h'01':1}, null, h''])` → `ErrMalformed`, no panic | `TestUnmarshalBstrLabel` | Yes |
| `VerifyMulti` with no matching verifier → `ErrVerification` | `TestVerifyMultiFailClosed` | Yes |
| External AAD round-trips through `ComputeMACMulti`/`VerifyMACMulti` and `EncryptMulti`/`DecryptMulti` | `TestMultiExternalAAD` | Yes |
| PBES2 header count > `MaxCount`, 0, or negative → `ErrDecryption` without running PBKDF2 | `TestPBES2CountBound` (bench asserts <1ms) | Yes |
| `Headers.Set(1, AlgES256)` encodes `a10126`; `SetChecked` with an unsupported type → `ErrUnsupportedHeader`; `Set` with one makes the next `Marshal*` fail with `ErrUnsupportedHeader` | `TestHeadersSetTypes`, `TestHeadersSetDeferredError` | Yes |
| Oversize R/S DER from a mock `crypto.Signer` → `ErrInvalidKey`, no panic | `TestDERToRawOversize` | Yes |
| `Verify` on detached message without payload → `ErrMissingPayload` | `TestVerifyDetachedMissing` | Yes |
| `errors.Is(err, corecbor.ErrTruncated)` holds through `UnmarshalSign1` | `TestUnmarshalErrorChain` | Yes |
| Concurrent `Verify` of one `*Sign1` from 8 goroutines is race-free | `go test -race -run TestConcurrentVerify` | Yes |
| Fuzz targets run 60s clean in CI | see Test surface | Yes |
| RFC 9053 vendored to `engineering-docs/rfcs/rfc9053.txt` (cited above) | file present + `rfcs/README.md` row | Yes |
| Each legacy selector above reproduces v0.2.2 acceptance on its fixture (message with unprotected alg, unknown `crit` label, duplicate label, 16-byte HMAC-256 key) and the default rejects it | `TestCompatLegacyVerify*` vs `testdata/legacy-v0.2.2/` | Yes |
| Legacy selectors and `DecodeLimits.AllowDuplicateLabels` carry `// Deprecated:` with removal floor v0.5.0; none appears in any `CompatV02*` bundle | staticcheck SA1019 fixture + `TestCompatBundlesExcludeWeakening` | Yes |
| A message with payload `h''` (empty, not detached) verifies | `TestVerifyEmptyPayload` | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |
| `UnmarshalSign1` accepts every v0.2.2 golden message (no new size/depth limits); `UnmarshalSign1With(data, RecommendedDecodeLimits)` rejects a 2 MiB message | `TestUnmarshalLimitsUnchanged`, `TestUnmarshalRecommendedLimits` | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 1 | Panics and fail-open: H5, H6, H8, nil guards, DER bounds, H11, H1 (protected bstr retention) | Done | first nine panic/fail-open rows green |
| 2 | Policy: H2 alg binding, H3 crit, H4 duplicates, H7 external AAD, HMAC key length | Done | policy rows green |
| 3 | Hygiene: H9 Set typing, H10 concurrency docs and race test, H13 error chains, decode limits | Done | remaining rows green |
| 4 | Fuzz targets wired into `make fuzz` | Done locally (FuzzUnmarshalNeverPanics, FuzzHeadersDecode, FuzzSign1RoundTrip, FuzzVerifyNeverPanics); CI pending | CI 60s clean |

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `FuzzUnmarshalNeverPanics` | arbitrary bytes → every `Unmarshal*` returns value or typed error | `cose/fuzz_test.go` |
| `FuzzSign1RoundTrip` | Sign → Marshal → Unmarshal → Verify | same |
| `FuzzHeadersDecode` | arbitrary protected bstr → `decodeProtected` | same |
| `TestVerifyForeignProtectedOrder` et al. | items above | `cose/hardening_test.go` |
| Interop vectors | COSE WG examples (cose-wg/Examples) for Sign1/Mac0/Encrypt0 verify-only | `cose/testdata/cose-wg/` |

---

## Performance

Removing the protected-header cache does not cost re-encoding on the verify
path, because verify uses `raw`. Signing pre-encodes once in `NewSigner`
(`sign.go:51`), as it does today.

| Metric | Target | Test mechanism |
|---|---|---|
| `BenchmarkVerifySign1ES256` | no regression > 3% vs `bench-020-baseline.txt` | `go test -bench VerifySign1 ./cose` |
| `BenchmarkUnmarshalSign1` | ≤ +1 alloc (duplicate-key check) | same |

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Strict `alg` binding rejects messages from lax producers that omit protected `alg` | med | med | `WithAllowedAlgorithms` plus a documented `WithLegacyAlgFromKey()` escape hatch, off by default |
| Callers keep using deprecated `Set` and learn about bad values late | med | low | `Marshal*` fails loudly with `ErrUnsupportedHeader`; staticcheck SA1019 points to `SetChecked` |
| Duplicate rejection breaks a known producer | low | low | no known producer emits duplicate COSE labels; RFC 9052 §3 forbids them |
| HMAC key-length minimum rejects existing short test keys | med | low | update tests; error names the minimum |

---

## Alternatives considered

- **Canonicalize instead of preserve.** Re-encode the received protected
  map deterministically and require the sender to have done the same.
  Rejected because RFC 9052 does not require deterministic protected
  headers, so we would reject valid messages.
- **Infer `alg` from the key only (status quo), documented.** Rejected:
  RFC 9052 §8.1 and RFC 9864 both expect the message `alg` to drive
  processing, and inference breaks once one key type supports more than
  one algorithm.
- **Make `VerifyMulti` return `bool`.** Rejected because callers need the
  verified indices. Fail-closed on `err` plus a policy enum keeps the
  current shape.

---

## Open questions

- Should `Verify` accept `alg` in the unprotected bucket under a legacy
  option? RFC 9052 permits it for some structures. Recommendation: no for
  Sign1, Sign and Mac; allowed for Recipient structures.
- Default `MaxCount` for PBES2: OWASP 2023 suggests 600 000 for
  PBKDF2-SHA256. The proposal uses 1 000 000 as the ceiling.

---

## Cross-references

- RFCs: RFC 9052 §3 (header buckets, `crit`), §4.4 (Sig_structure), §6.3,
  §5.3; RFC 9053 §3.1 (HMAC), §6.4 (PBES2 not registered in COSE)
- Sibling proposals: 002, 011, 017, 021, 022, 028 (header accessors build
  on the duplicate rule), 029 (algorithm identifiers, PBES2 id)
- External: IANA COSE registries (fetched 2026-11-20); cose-wg/Examples

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from code review and probe findings | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-20 | Phase 1 implemented (H1, H5, H6, H8, H11, nil guards, DER bounds, DecryptMulti IV); fuzz targets for Phase 1 surfaces; status In-Progress | corecbor maintainers |
| 2026-11-20 | Decisions: H2 unprotected-alg rule; nil payload = detached; runnable payload examples | corecbor maintainers |
| 2026-11-20 | Phase 2 done: alg binding (decided rule), crit, duplicate labels, multi external AAD and alg allow-lists, HMAC key checks; implementation notes | corecbor maintainers |
| 2026-11-20 | Phase 3 done: SetChecked + typed Set, copy-safe headers, error chains, Unmarshal*With/DecodeLimits; Phase 4 targets complete locally | corecbor maintainers |
| 2026-11-21 | Status: Closed (Phases 1–4 on main; CI green incl. cose fuzz, run 44880682829) | corecbor maintainers |
