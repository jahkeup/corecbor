# 002 — COSE structures and cryptographic operations (RFC 9052 + RFC 9053)

## Header

| Field | Value |
|---|---|
| **Number** | 002 |
| **Tier** | 3 |
| **Status** | Accepted |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (Phase 1 — foundational primitives) |
| **Supersedes** | none |
| **Spec sections touched** | none (tier-3; lives outside corecbor proper) |

---

## TL;DR

Implement CBOR Object Signing and Encryption (COSE) per RFC 9052
(structures/process) and RFC 9053 (algorithms) as a sibling Go module
(`github.com/jahkeup/corecbor/cose`) that depends on corecbor's
`cbor` and `rfc8949` packages for CBOR encoding plus Go 1.25+ stdlib
`crypto/*` for all cryptographic operations.

COSE is overwhelmingly a "typed structures" layer: the six message
types (Sign, Sign1, Encrypt, Encrypt0, Mac, Mac0) plus Key/KeySet are
CBOR arrays and maps with fixed field layouts.  The cryptographic
"work" delegates entirely to stdlib primitives — EdDSA, ECDSA, AES-GCM,
HMAC, HKDF, ECDH.  Three small algorithms not in stdlib (AES-KW,
AES-CMAC, AES-CCM) are self-contained implementations totaling ~330 LOC
and live inside the COSE module with no external deps.

This is tier-3 (separate module, independent of corecbor's contract)
and blocked on Phase 1 closing.  It MAY proceed in parallel with
Phases 2–4 of corecbor since it depends only on the Phase 1 surface.

---

## Motivation

COSE is the standard cryptographic envelope for CBOR-encoded data.
Downstream consumers of corecbor — notably anything in the WebAuthn /
FIDO2 / CWT (CBOR Web Token) / EAT (Entity Attestation Token) space —
need COSE operations immediately after basic CBOR encode/decode lands.

Beyond the standard signing/encryption use cases, COSE's multi-recipient
`COSE_Encrypt` structure and extensible algorithm registry make it
suitable for **key escrow and derived-key setups** — the same class of
problems that Clevis (currently JOSE/JWE-based) solves:

- **Network-bound encryption** (Tang-style): ECDH key agreement with a
  remote server → HKDF-derived KEK → AES-KW wraps the CEK.  Maps
  directly to COSE's `ECDH-ES+A256KW` recipient algorithm.
- **Hardware-bound encryption** (TPM-style): External key material
  provided by a TPM unseal → `COSE_Encrypt0` with `AlgDirect`.  The
  COSE envelope holds ciphertext; key sourcing is out-of-band.
- **Multi-recipient / any-of-N unlock**: Multiple `COSE_recipient`
  entries, each independently able to unwrap the CEK via different
  mechanisms (different servers, different TPMs, different passwords).
- **Nested key wrapping**: `COSE_recipient` supports recursive nesting
  (RFC 9052 Appendix B) — a recipient's key can itself be wrapped by
  another recipient, enabling key escrow chains.
- **Custom pin protocols**: The algorithm extensibility interface
  (see §"Algorithm extensibility" below) allows Clevis-like "pin"
  implementations to register as COSE recipient algorithms, so the
  Tang protocol's specific key-recovery dance or a Shamir
  reconstruction step can plug in without forking the COSE module.
- **Password-based key derivation**: PBES2 (PBKDF2 + AES-KW) recipient
  algorithms allow password-protected encryption envelopes.

Today in the Go ecosystem, COSE libraries either:

1. Bundle their own CBOR codec (duplicating effort, different quirk
   handling, different strictness posture).
2. Depend on `fxamacker/cbor` or `ugorji/go` — pulling in a large
   dependency for what is fundamentally a typed-structure problem.
3. Are incomplete or abandoned.
4. Do not expose extensible algorithm interfaces, preventing custom
   key-distribution mechanisms (Tang, TPM, Shamir) from plugging in.

A COSE module that consumes corecbor's value-tree API directly gets:

- Deterministic encoding of the `Sig_structure` / `Enc_structure` /
  `MAC_structure` via corecbor's `CoreDeterministic` mode (the RFC
  9052 §9 encoding restriction is exactly corecbor's
  `ModeCoreDeterministic`).
- Forgiving decode of peer-produced COSE messages via corecbor's
  knob-based decoder.
- Zero duplicated CBOR logic.
- Zero non-stdlib runtime dependencies (the COSE module imports only
  corecbor + stdlib crypto).
- An extensible algorithm registry that supports custom key-distribution
  mechanisms for escrow/derived-key systems.

### Why stdlib crypto suffices

The Go 1.25+ stdlib provides:

| COSE need | stdlib package |
|---|---|
| EdDSA (Ed25519) | `crypto/ed25519` |
| ECDSA (P-256, P-384, P-521) | `crypto/ecdsa` |
| AES-GCM (128/192/256) | `crypto/aes` + `crypto/cipher` |
| HMAC (SHA-256/384/512) | `crypto/hmac` + `crypto/sha256`/`sha512` |
| HKDF (SHA-256/384/512) | `crypto/hkdf` |
| ECDH (P-256/384/521, X25519) | `crypto/ecdh` |
| HPKE (RFC 9180) | `crypto/hpke` |
| PBKDF2 | `crypto/pbkdf2` |
| SHA-3 | `crypto/sha3` |

Three small algorithms require self-contained implementations:

| Algorithm | LOC | Spec | Use case |
|---|---|---|---|
| AES-KW (Key Wrap) | ~50 | RFC 3394 | Key wrapping recipients |
| AES-CMAC | ~80 | RFC 4493 / NIST SP 800-38B | AES-MAC auth tag |
| AES-CCM | ~200 | RFC 3610 / NIST SP 800-38C | IoT/CoAP content encryption |

These are well-specified block-cipher constructions over `crypto/aes`
and do not require external dependencies.

---

## Proposal

### Module structure

```
github.com/jahkeup/corecbor/cose/       # go.mod: module github.com/jahkeup/corecbor/cose
├── doc.go                              # Package doc
├── message.go                          # COSE_Sign, COSE_Sign1, COSE_Encrypt, COSE_Encrypt0,
│                                       # COSE_Mac, COSE_Mac0 types
├── headers.go                          # Protected / Unprotected header parameter types
├── key.go                              # COSE_Key, COSE_KeySet types + stdlib key conversion
├── sign.go                             # Sign / Verify operations (Sign1 + Sign multi)
├── encrypt.go                          # Encrypt / Decrypt operations (Encrypt0 + Encrypt multi)
├── mac.go                              # MAC create / verify operations (Mac0 + Mac multi)
├── algorithms.go                       # Algorithm registry (label → stdlib dispatch)
├── keyderiver.go                       # KeyDeriver interface + RegisterKeyDeriver + built-in derivers
├── pbes2.go                            # PBES2 (PBKDF2 + AES-KW) recipient algorithm
├── structures.go                       # Sig_structure, Enc_structure, MAC_structure builders
├── internal/
│   ├── aeskw/                          # AES Key Wrap (RFC 3394)
│   │   ├── aeskw.go
│   │   └── aeskw_test.go
│   ├── aescmac/                        # AES-CMAC (RFC 4493)
│   │   ├── cmac.go
│   │   └── cmac_test.go
│   └── aesccm/                         # AES-CCM (RFC 3610)
│       ├── ccm.go
│       └── ccm_test.go
├── sign_test.go
├── encrypt_test.go
├── mac_test.go
├── key_test.go
├── cose_test.go                        # RFC 9052 Appendix C vectors
├── examples_test.go                    # Tang-style, TPM-style, threshold pattern examples
└── testdata/
    └── rfc9052-appendix-c/             # Vendored test vectors
```

### Dependency graph

```
crypto/ed25519 ─┐
crypto/ecdsa ───┤
crypto/ecdh ────┤
crypto/aes ─────┼──► github.com/jahkeup/corecbor/cose
crypto/cipher ──┤        │
crypto/hmac ────┤        ▼
crypto/hkdf ────┤   github.com/jahkeup/corecbor/cbor     (Value types, errors)
crypto/sha256 ──┤   github.com/jahkeup/corecbor/wire     (optional: head encoding)
crypto/sha512 ──┤   github.com/jahkeup/corecbor/rfc8949  (CoreDeterministic encode)
crypto/hpke ────┘
```

No non-stdlib, non-corecbor dependencies.

### Public API surface

```go
package cose

import (
    "github.com/jahkeup/corecbor/cbor"
)

// ---- Message types (RFC 9052 §4–6) ----

// Sign1 is a COSE_Sign1 message (CBOR tag 18).
// Single signer, the common case.
type Sign1 struct {
    Protected   Headers
    Unprotected Headers
    Payload     []byte   // nil = detached
    Signature   []byte
}

// Sign is a COSE_Sign message (CBOR tag 98). Multiple signers.
type Sign struct {
    Protected   Headers
    Unprotected Headers
    Payload     []byte
    Signatures  []Signature
}

type Signature struct {
    Protected   Headers
    Unprotected Headers
    Signature   []byte
}

// Encrypt0 is a COSE_Encrypt0 message (CBOR tag 16).
// Single recipient, pre-shared key.
type Encrypt0 struct {
    Protected   Headers
    Unprotected Headers
    Ciphertext  []byte // nil = detached
}

// Encrypt is a COSE_Encrypt message (CBOR tag 96).
type Encrypt struct {
    Protected   Headers
    Unprotected Headers
    Ciphertext  []byte
    Recipients  []Recipient
}

type Recipient struct {
    Protected   Headers
    Unprotected Headers
    Ciphertext  []byte       // encrypted CEK; nil for direct
    Recipients  []Recipient  // nested recipients (Appendix B)
}

// Mac0 is a COSE_Mac0 message (CBOR tag 17).
type Mac0 struct {
    Protected   Headers
    Unprotected Headers
    Payload     []byte
    Tag         []byte
}

// Mac is a COSE_Mac message (CBOR tag 97).
type Mac struct {
    Protected   Headers
    Unprotected Headers
    Payload     []byte
    Tag         []byte
    Recipients  []Recipient
}

// ---- Headers (RFC 9052 §3) ----

// Headers is the COSE header parameter map.
// Integer labels (1–6) are the common parameters;
// additional parameters use arbitrary int/tstr labels.
type Headers struct {
    params map[any]cbor.Value // int64 or string keys
}

// Algorithm constants (RFC 9053 §2).
type Algorithm int64

const (
    AlgEdDSA      Algorithm = -8
    AlgES256      Algorithm = -7
    AlgES384      Algorithm = -35
    AlgES512      Algorithm = -36
    AlgHMAC256_64 Algorithm = 4
    AlgHMAC256    Algorithm = 5
    AlgHMAC384    Algorithm = 6
    AlgHMAC512    Algorithm = 7
    AlgAESGCM128  Algorithm = 1
    AlgAESGCM192  Algorithm = 2
    AlgAESGCM256  Algorithm = 3
    AlgAESCCM_16_64_128  Algorithm = 10
    AlgAESCCM_16_64_256  Algorithm = 11
    AlgAESCCM_64_64_128  Algorithm = 12
    AlgAESCCM_64_64_256  Algorithm = 13
    AlgAESCCM_16_128_128 Algorithm = 30
    AlgAESCCM_16_128_256 Algorithm = 31
    AlgAESCCM_64_128_128 Algorithm = 32
    AlgAESCCM_64_128_256 Algorithm = 33
    AlgA128KW     Algorithm = -3
    AlgA192KW     Algorithm = -4
    AlgA256KW     Algorithm = -5
    AlgDirect     Algorithm = -6
    AlgECDH_ES_HKDF_256 Algorithm = -25
    AlgECDH_ES_HKDF_512 Algorithm = -26
    AlgECDH_SS_HKDF_256 Algorithm = -27
    AlgECDH_SS_HKDF_512 Algorithm = -28
    AlgECDH_ES_A128KW   Algorithm = -29
    AlgECDH_ES_A192KW   Algorithm = -30
    AlgECDH_ES_A256KW   Algorithm = -31
    AlgECDH_SS_A128KW   Algorithm = -32
    AlgECDH_SS_A192KW   Algorithm = -33
    AlgECDH_SS_A256KW   Algorithm = -34

    // Password-based key derivation (PBES2, RFC 8152 §12.3)
    // Enables password-protected encryption envelopes for key
    // escrow systems (Clevis-style password pins).
    AlgPBES2_HS256_A128KW Algorithm = -100  // PBKDF2-SHA-256 + AES-128-KW
    AlgPBES2_HS256_A192KW Algorithm = -101  // PBKDF2-SHA-256 + AES-192-KW
    AlgPBES2_HS256_A256KW Algorithm = -102  // PBKDF2-SHA-256 + AES-256-KW
    AlgPBES2_HS384_A192KW Algorithm = -103  // PBKDF2-SHA-384 + AES-192-KW
    AlgPBES2_HS384_A256KW Algorithm = -104  // PBKDF2-SHA-384 + AES-256-KW
    AlgPBES2_HS512_A256KW Algorithm = -105  // PBKDF2-SHA-512 + AES-256-KW
)

// ---- Key types (RFC 9052 §7) ----

// Key is a COSE_Key (CBOR map with integer labels).
type Key struct {
    Type      KeyType
    ID        []byte     // kid
    Algorithm Algorithm  // alg (optional restriction)
    Ops       []KeyOp    // key_ops
    BaseIV    []byte
    params    map[int64]cbor.Value // type-specific params
}

type KeyType int64

const (
    KeyTypeOKP KeyType = 1 // Octet Key Pair (Ed25519, X25519)
    KeyTypeEC2 KeyType = 2 // Elliptic Curve (P-256, P-384, P-521)
    KeyTypeSymmetric KeyType = 4
)

type KeyOp int64

const (
    KeyOpSign    KeyOp = 1
    KeyOpVerify  KeyOp = 2
    KeyOpEncrypt KeyOp = 3
    KeyOpDecrypt KeyOp = 4
    KeyOpWrapKey   KeyOp = 5
    KeyOpUnwrapKey KeyOp = 6
    KeyOpDeriveKey  KeyOp = 7
    KeyOpDeriveBits KeyOp = 8
    KeyOpMACCreate  KeyOp = 9
    KeyOpMACVerify  KeyOp = 10
)

// KeySet is a COSE_KeySet (CBOR array of Keys).
type KeySet []Key

// ---- Algorithm extensibility (key escrow / custom pins) ----

// KeyDeriver is the interface for custom key-distribution algorithms.
// Implementations produce or recover a content encryption key (CEK)
// from a COSE_recipient structure.  This enables Tang-style network
// escrow, TPM-bound keys, Shamir reconstruction, or any custom
// "pin" protocol to participate as a COSE recipient algorithm.
//
// The interface intentionally mirrors COSE's recipient processing model:
// the WrapKey direction runs at encryption time (escrow the CEK),
// the UnwrapKey direction runs at decryption time (recover the CEK).
type KeyDeriver interface {
    // Algorithm returns the COSE algorithm ID for this deriver.
    // Custom algorithms use values from the private-use range
    // (less than -65536) or text-string labels.
    Algorithm() Algorithm

    // WrapKey encrypts/escrows the CEK, producing the ciphertext
    // to store in the COSE_recipient.  The protected/unprotected
    // headers carry algorithm-specific parameters (e.g., a Tang
    // server URL, a TPM PCR policy hash, a salt for PBKDF2).
    //
    // Returns the recipient ciphertext (wrapped key material) and
    // any headers the algorithm needs to store.
    WrapKey(cek []byte, opts KeyWrapOpts) (ciphertext []byte, headers Headers, err error)

    // UnwrapKey recovers the CEK from the COSE_recipient structure.
    // The implementation may perform network calls (Tang), hardware
    // operations (TPM unseal), or threshold reconstruction (Shamir).
    //
    // For direct key agreement (where ciphertext is nil), the CEK
    // is derived directly from the key agreement output.
    UnwrapKey(ciphertext []byte, headers Headers, opts KeyUnwrapOpts) (cek []byte, err error)
}

// KeyWrapOpts carries context for key wrapping.
type KeyWrapOpts struct {
    // CEKAlgorithm is the algorithm the CEK will be used with
    // (needed by some KDFs for context binding).
    CEKAlgorithm Algorithm

    // CEKLength is the required key length in bytes.
    CEKLength int

    // Protected and Unprotected from the content layer,
    // available for context binding.
    ContentProtected Headers
}

// KeyUnwrapOpts mirrors KeyWrapOpts for the unwrap direction.
type KeyUnwrapOpts struct {
    CEKAlgorithm     Algorithm
    CEKLength        int
    ContentProtected Headers
}

// RegisterKeyDeriver registers a custom key-distribution algorithm.
// After registration, COSE_Encrypt messages using this algorithm ID
// will dispatch to the registered KeyDeriver for key wrap/unwrap.
//
// Built-in algorithms (Direct, AES-KW, ECDH-ES, ECDH-ES+AKW, PBES2)
// are pre-registered.  Custom algorithms SHOULD use IDs in the
// private-use range (< -65536) to avoid collision with IANA-assigned
// values.
//
// This function is NOT safe for concurrent use; call during init().
func RegisterKeyDeriver(d KeyDeriver)

// ---- Operations ----

// Signer creates COSE signatures.
type Signer struct {
    key        crypto.Signer
    algorithm  Algorithm
    protected  Headers
}

// NewSigner creates a signer from a stdlib crypto.Signer.
func NewSigner(key crypto.Signer, opts ...SignerOption) (*Signer, error)

// Sign1Message creates a COSE_Sign1 from payload.
func (s *Signer) Sign1(payload, external []byte) (*Sign1, error)

// Verifier verifies COSE signatures.
type Verifier struct {
    key       crypto.PublicKey
    algorithm Algorithm
}

// NewVerifier creates a verifier from a stdlib public key.
func NewVerifier(key crypto.PublicKey, opts ...VerifierOption) (*Verifier, error)

// Verify1 verifies a COSE_Sign1 message.
func (v *Verifier) Verify1(msg *Sign1, external []byte) error

// ---- Encoding / Decoding (via corecbor) ----

// Marshal encodes a COSE message to CBOR using CoreDeterministic
// encoding for the internal structures (per RFC 9052 §9) and the
// specified mode for the outer envelope.
func Marshal(msg any) ([]byte, error)

// Unmarshal decodes a tagged COSE message from CBOR bytes.
// Uses corecbor's forgiving decoder.
func Unmarshal(data []byte) (any, error)

// UnmarshalSign1 decodes a COSE_Sign1 specifically.
func UnmarshalSign1(data []byte) (*Sign1, error)

// ---- Key conversion (COSE Key ↔ stdlib) ----

// NewKeyFromCrypto converts a stdlib crypto key to a COSE_Key.
func NewKeyFromCrypto(key crypto.PublicKey) (*Key, error)

// CryptoPublicKey extracts the stdlib crypto.PublicKey from a COSE_Key.
func (k *Key) CryptoPublicKey() (crypto.PublicKey, error)

// CryptoSigner extracts a crypto.Signer from a COSE_Key with private
// key material.  Returns an error if the key has no private params.
func (k *Key) CryptoSigner() (crypto.Signer, error)
```

### Behavior

COSE operations follow this pattern:

1. **Construct canonical structure** — Build the `Sig_structure`,
   `Enc_structure`, or `MAC_structure` as a corecbor `cbor.Array`.

2. **Encode to bytes** — Encode that structure using corecbor's
   `rfc8949.EncodeDeterministic()` (satisfying RFC 9052 §9:
   definite lengths, shortest arguments).

3. **Call stdlib crypto** — Pass the encoded bytes to the appropriate
   stdlib function (e.g., `ed25519.Sign`, `ecdsa.SignASN1`,
   `cipher.AEAD.Seal`).

4. **Assemble message** — Place the result into the COSE message
   structure and encode the outer message.

This means the COSE package is a thin typed layer:
- Types define CBOR array/map layouts (per RFC 9052 §§4–7).
- Algorithms dispatch to stdlib (per RFC 9053).
- corecbor handles all CBOR encoding/decoding.

### CBOR encoding restrictions (RFC 9052 §9)

RFC 9052 §9 mandates that the internal structures (`Sig_structure`,
`Enc_structure`, `MAC_structure`) use:

- Definite lengths
- Shortest argument encoding

This is exactly corecbor's `ModeCoreDeterministic` minus map key
sorting (these structures are arrays, not maps, so sorting is N/A).
The COSE module uses corecbor's deterministic encoder for these
internal structures, verifying that the corecbor contract and the
COSE contract are aligned by design.

### Shadow / deprecation strategy

RFC 9052 obsoletes RFC 8152. The COSE module targets 9052 exclusively.
If a future RFC supersedes 9052:

1. Add a sibling package (e.g., `cose/v2` or `cose/rfcNNNN`)
   implementing the new structures/algorithms.
2. The old package gains a `// Deprecated:` doc comment.
3. Shared types (Algorithm constants, Key types) that are unchanged
   get re-exported from a common internal package.
4. The outer API can version-gate at construction time if both must
   coexist.

For algorithm additions (new RFCs registering new COSE algorithm IDs):
- New constants are added to `algorithms.go`.
- New dispatch functions implement the algorithm.
- No structural change to existing code.

### Failure modes

```go
var (
    ErrUnsupportedAlgorithm = errors.New("cose: unsupported algorithm")
    ErrVerification         = errors.New("cose: verification failed")
    ErrDecryption           = errors.New("cose: decryption failed")
    ErrInvalidKey           = errors.New("cose: key type does not match algorithm")
    ErrMissingPayload       = errors.New("cose: payload is nil and no external payload supplied")
    ErrDuplicateLabel       = errors.New("cose: duplicate label in header map")
    ErrCriticalHeader       = errors.New("cose: unprocessed critical header parameter")
    ErrMalformedMessage     = errors.New("cose: message is not well-formed COSE")
)
```

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| RFC 9052 Appendix C vectors round-trip | Vendored vectors in `testdata/rfc9052-appendix-c/`; each example decodes + re-encodes byte-identical | Yes |
| Sign1 + Verify1 round-trip (EdDSA, ES256, ES384, ES512) | Typed test per algorithm | Yes |
| Encrypt0 + Decrypt round-trip (AES-GCM-128/256) | Typed test per algorithm | Yes |
| Mac0 + Verify round-trip (HMAC-256, HMAC-512) | Typed test per algorithm | Yes |
| COSE_Key ↔ stdlib key conversion round-trip | `TestKeyConversion_*` per key type (OKP, EC2, Symmetric) | Yes |
| Internal structures encode per RFC 9052 §9 | Assert deterministic encoding (definite length, shortest args) for Sig_structure/Enc_structure/MAC_structure | Yes |
| Duplicate header label rejection | `TestHeaders_RejectDuplicateLabels` | Yes |
| Critical header parameter enforcement | `TestCritical_UnprocessedHeaderFails` | Yes |
| AES-KW implementation passes RFC 3394 vectors | `internal/aeskw/aeskw_test.go` table test | Yes |
| AES-CCM implementation passes RFC 3610 vectors | `internal/aesccm/ccm_test.go` table test | Yes |
| AES-CMAC implementation passes RFC 4493 vectors | `internal/aescmac/cmac_test.go` table test | Yes |
| No non-stdlib, non-corecbor runtime deps | `go mod graph` shows only corecbor + stdlib | Yes |
| FuzzUnmarshalNeverPanics (arbitrary bytes → Unmarshal) | Fuzz target, 30s clean | Yes |
| Custom `KeyDeriver` registers and participates in Encrypt/Decrypt round-trip | `TestCustomKeyDeriver_RoundTrip`: register a mock deriver, encrypt with it, decrypt recovers plaintext | Yes |
| PBES2 password-based recipient round-trips | `TestPBES2_RoundTrip`: encrypt with password, decrypt with same password succeeds, wrong password fails with `ErrDecryption` | Yes |
| Multi-recipient any-of-N unlock | `TestMultiRecipient_AnyCanDecrypt`: 3 recipients (ECDH-ES, Direct, PBES2); each independently decrypts the same ciphertext | Yes |
| Nested recipient structure | `TestNestedRecipient_KeyEscrowChain`: CEK wrapped by KEK, KEK wrapped by another key; full chain unwraps | Yes |
| Zero-alloc signing (pre-allocated Signer, small payload) | Benchmark + `-benchmem` | No (measured, not gated) |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Types + Sign1/Verify1 (EdDSA + ECDSA) + Marshal/Unmarshal + Key conversion | Pending | RFC 9052 Appendix C signing vectors pass |
| B | Encrypt0/Encrypt + Mac0/Mac + AES-GCM + HMAC + HKDF recipients + `KeyDeriver` interface | Pending | Appendix C encryption/MAC vectors pass; custom KeyDeriver registers and round-trips |
| C | Extended algorithms: AES-CCM, AES-KW, AES-CMAC, ECDH+KW recipients, PBES2 recipients | Pending | All RFC 9053 algorithms w/ test vectors; PBES2 password-encrypt round-trips |
| D | HPKE integration (RFC 9180 via `crypto/hpke`) | Pending | HPKE-based recipients tested |
| E | Key escrow examples + Clevis-equivalent patterns (Tang-style, direct/TPM-style, threshold) | Pending | Example tests demonstrate multi-recipient escrow with custom KeyDeriver |

Phase A is independently shippable — it covers the WebAuthn/FIDO2 and
CWT use cases that only need Sign1.

Phase B introduces the `KeyDeriver` extensibility interface alongside
the standard encryption recipient types.  This unblocks Phase E
(escrow patterns) while keeping Phase C focused on the remaining
IANA-registered algorithms.

Phase E is intentionally last — it builds example patterns and
optional helper packages (e.g., `cose/shamir`) on top of the
fully-realized algorithm set from Phases B–D.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestRFC9052AppendixC_Sign` | All signing vectors from RFC 9052 | `cose_test.go` |
| `TestRFC9052AppendixC_Encrypt` | All encryption vectors | `cose_test.go` |
| `TestRFC9052AppendixC_MAC` | All MAC vectors | `cose_test.go` |
| `TestRFC9052AppendixC_Keys` | Key encoding vectors | `key_test.go` |
| `TestSign1_RoundTrip_*` | Per-algorithm sign+verify | `sign_test.go` |
| `TestEncrypt0_RoundTrip_*` | Per-algorithm encrypt+decrypt | `encrypt_test.go` |
| `TestMac0_RoundTrip_*` | Per-algorithm MAC | `mac_test.go` |
| `TestKeyConversion_*` | COSE Key ↔ stdlib key | `key_test.go` |
| `TestSigStructure_Deterministic` | §9 encoding restriction | `structures_test.go` |
| `FuzzUnmarshalNeverPanics` | Adversarial CBOR → no panic | `cose_fuzz_test.go` |
| `FuzzSign1RoundTrip` | Sign→Marshal→Unmarshal→Verify | `cose_fuzz_test.go` |
| `TestAESKW_RFC3394Vectors` | AES Key Wrap | `internal/aeskw/aeskw_test.go` |
| `TestAESCCM_RFC3610Vectors` | AES-CCM | `internal/aesccm/ccm_test.go` |
| `TestAESCMAC_RFC4493Vectors` | AES-CMAC | `internal/aescmac/cmac_test.go` |
| `TestCustomKeyDeriver_RoundTrip` | Extensibility interface works end-to-end | `encrypt_test.go` |
| `TestPBES2_RoundTrip` | Password-based encryption | `encrypt_test.go` |
| `TestMultiRecipient_AnyCanDecrypt` | N recipients, each can independently unwrap | `encrypt_test.go` |
| `TestNestedRecipient_KeyEscrowChain` | Recursive recipient unwrapping | `encrypt_test.go` |
| `TestKeyDeriver_TangStyle` | ECDH+HKDF custom deriver (simulates Tang) | `examples_test.go` |
| `TestKeyDeriver_DirectTPMStyle` | Direct key from external source | `examples_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| Sign1 (Ed25519, 1KB payload) | ≥ 10,000 ops/s | `BenchmarkSign1_Ed25519` |
| Verify1 (Ed25519, 1KB payload) | ≥ 10,000 ops/s | `BenchmarkVerify1_Ed25519` |
| Encrypt0 (AES-GCM-256, 1KB payload) | ≥ 500 MB/s throughput | `BenchmarkEncrypt0_AESGCM256` |
| Marshal Sign1 (pre-signed, encoding only) | 0 allocations | `-benchmem` |
| Unmarshal Sign1 | ≤ 3 allocations | `-benchmem` |

Performance targets are informational for Phase A; gating after Phase D.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| corecbor Phase 1 interface instability | medium | medium | COSE module pins a specific corecbor version; interface is minimal (encode/decode Value trees) |
| AES-CCM implementation correctness | low | high (crypto) | RFC 3610 test vectors + third-party cross-validation against `x/crypto` reference |
| Algorithm ID space evolves (new IANA registrations) | high | low | Algorithm constants are extensible; callers can register custom algorithms via `KeyDeriver` |
| ChaCha20-Poly1305 desire creates pressure for `x/crypto` dep | medium | low | Defer to a build-tag-gated optional file or accept the single `x/crypto` dep as tier-2 enhancement |
| COSE_Sign (multi-signer) complexity exceeds budget | low | low | Phase A ships Sign1 only; multi-signer is Phase B |
| Ed448 demand | low | low | Not in Go stdlib; defer until `crypto/ed448` lands or accept `x/crypto` dep |
| `KeyDeriver` interface is too narrow for some exotic algorithms | medium | medium | Interface covers the 5 RFC 9052 §8.5 classes; if a future algorithm class doesn't fit, a v2 interface can extend without breaking v1 callers |
| Custom `KeyDeriver` implementations may have timing side-channels | medium | high (crypto) | Document that `UnwrapKey` implementations MUST use constant-time comparison for key material; provide a `subtle.ConstantTimeCompare` helper note in godoc |
| Shamir/threshold schemes require application-level coordination | low | low | Phase E provides example patterns; the `KeyDeriver` interface handles individual shares, not the orchestration of collecting K shares from N parties |

---

## Alternatives considered

### Use `veraison/go-cose` or `pion/cose`

Rejected. Existing Go COSE libraries either bring their own CBOR codec
(misaligned strictness, different round-trip behavior) or depend on
`fxamacker/cbor`. The purpose of corecbor is to be the foundation; a
COSE module that isn't built on corecbor defeats the point.

### Put COSE in the corecbor module itself (not a sibling module)

Rejected. COSE brings crypto imports that corecbor-only consumers
don't need. Separate `go.mod` keeps corecbor's dependency closure at
zero (stdlib + gofumpt tooling only) while COSE adds only corecbor +
stdlib crypto.

### Implement only Sign1 (skip Encrypt/Mac)

Rejected as the full scope, but accepted as the phasing strategy.
Phase A ships Sign1 (covers WebAuthn/CWT); Phases B–D extend.  The
proposal captures the full scope so that API design accounts for all
message types from the start.

### Accept `golang.org/x/crypto` as a dependency for ChaCha20-Poly1305

Deferred. The core COSE profiles (WebAuthn, CWT, EAT) use AES-GCM and
EdDSA — both stdlib. ChaCha20-Poly1305 is a "nice to have" for
protocols that prefer it.  If demand materializes, it can be added as
an optional algorithm behind a build tag or as a thin wrapper in a
`cose/x` sub-package that accepts the `x/crypto` dep.

### Closed algorithm set (no extensibility interface)

Rejected.  A closed set would be simpler but prevents key escrow /
derived-key systems (Clevis, Tang, TPM) from using COSE as their
envelope without forking.  The `KeyDeriver` interface adds minimal
complexity (two methods) while enabling the full taxonomy of RFC 9052
§8.5 recipient algorithm classes to be extended at runtime.  The
interface boundary (WrapKey/UnwrapKey operating on raw key bytes) is
narrow enough to avoid over-abstraction — it doesn't try to model the
entire key-agreement protocol, just the key-material exchange point
that COSE needs.

### Build Clevis-like orchestration into the COSE module

Rejected.  Clevis's pin orchestration (collecting shares, talking to
Tang servers, interacting with TPMs) is application-layer logic above
the cryptographic envelope.  The COSE module provides the `KeyDeriver`
hook point; a separate `cose/clevis` or `cose/escrow` package (Phase
E or beyond) provides the orchestration.  This keeps the core module
focused on RFC 9052 compliance.

---

## Open questions

- **Module path**: Should COSE be `github.com/jahkeup/corecbor/cose`
  (subdirectory with own `go.mod`) or a completely separate repo
  (`github.com/jahkeup/cose`)? Subdirectory keeps the ecosystem
  together; separate repo allows independent release cadence.
  Lean: subdirectory (monorepo with multiple modules).

- ~~**Algorithm extensibility**~~: **RESOLVED.** The COSE module
  exposes a `KeyDeriver` interface and a `RegisterKeyDeriver()`
  function for custom key-distribution algorithms.  This enables
  Clevis-like pin implementations (Tang, TPM, Shamir, password) to
  plug into COSE recipient processing without forking.  Built-in
  algorithms (Direct, AES-KW, ECDH-ES+HKDF, PBES2) are
  pre-registered via init().  Custom algorithms use private-use IDs
  (< -65536) or text-string labels.  The interface is intentionally
  narrow (WrapKey/UnwrapKey) to avoid over-abstraction while covering
  the full recipient-algorithm taxonomy from RFC 9052 §8.5.

- **COSE tag wrapping**: When marshaling, should the output always
  include the CBOR tag (e.g., tag 18 for Sign1), or should tagged
  vs untagged be caller-controlled? RFC 9052 §2 says both are valid
  depending on context. Lean: provide both `Marshal` (tagged) and
  `MarshalUntagged`, with tagged as the default.

- **Threshold/Shamir reconstruction ergonomics**: The `KeyDeriver`
  interface supports K-of-N schemes at the individual-share level
  (each share is a separate recipient whose `UnwrapKey` returns its
  share; a coordinating `KeyDeriver` implementation collects K shares
  and reconstructs).  Should the COSE module provide a built-in
  `ThresholdKeyDeriver` helper, or is that a separate package
  concern?  Lean: separate package (`cose/shamir` or similar) that
  implements `KeyDeriver` — keeps the core COSE module focused on
  RFC 9052 structure.

---

## Cross-references

- RFCs: `../rfcs/rfc9052.txt` — COSE structures and process (primary).
- RFCs: RFC 9053 (not vendored yet) — COSE algorithms.
  Vendor into `rfcs/rfc9053.txt` before Phase A implementation begins.
- RFCs: `../rfcs/rfc8949.txt` §4.2.1 — Core Deterministic Encoding
  (aligns with RFC 9052 §9 encoding restrictions).
- RFCs: RFC 3394 (AES Key Wrap), RFC 4493 (AES-CMAC),
  RFC 3610 (AES-CCM) — self-contained algorithm implementations.
- RFCs: RFC 8018 (PKCS#5 / PBKDF2) — via `crypto/pbkdf2` for PBES2.
- Sibling proposals: `001-phase-1-foundational-primitives.md` — COSE
  depends on Phase 1's Value types, encoder, and decoder.
- External: IANA COSE Algorithms registry:
  https://www.iana.org/assignments/cose/cose.xhtml
- External: Clevis framework (JOSE-based key escrow):
  https://github.com/latchset/clevis — motivating use case for
  `KeyDeriver` extensibility; demonstrates Tang, TPM2, Shamir pins.
- External: Tang protocol (network-bound encryption):
  https://github.com/latchset/tang — ECDH key recovery server that
  maps to COSE ECDH-ES recipient algorithms.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
| 2026-05-20 | Add KeyDeriver interface, PBES2 algorithms, key escrow motivation (Clevis use case), Phase E, resolve algorithm extensibility open question | corecbor maintainers |
