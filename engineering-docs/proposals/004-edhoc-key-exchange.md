# 004 — EDHOC: Ephemeral Diffie-Hellman Over COSE (RFC 9528)

## Header

| Field | Value |
|---|---|
| **Number** | 004 |
| **Tier** | 3 |
| **Status** | Draft |
| **Filed** | 2026-05-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 001 (corecbor primitives), 002 (COSE) |
| **Supersedes** | none |
| **Spec sections touched** | none (tier-3; sibling module) |

---

## TL;DR

Implement EDHOC (Ephemeral Diffie-Hellman Over COSE) per RFC 9528 as a
sibling Go module (`github.com/jahkeup/corecbor/edhoc`) that depends on
corecbor for CBOR encoding and the COSE module for key types and
cryptographic structures.

EDHOC is a lightweight authenticated key exchange protocol designed for
constrained IoT environments.  It produces an OSCORE security context
(shared secret + key material) from a 3-message handshake using COSE
key types and CBOR-encoded messages.  The protocol messages are CBOR
sequences; the key schedule uses HKDF; authentication uses COSE
signatures or MACs.

Unlike COSE (pure types + dispatch), EDHOC has **protocol state** — a
3-message handshake with a state machine.  However, the messages
themselves are CBOR-encoded structures, the cryptographic operations
use stdlib primitives (ECDH, HKDF, EdDSA/ECDSA), and the implementation
is self-contained (~800–1200 LOC) with zero non-stdlib runtime deps.

Blocked on proposal 002 (COSE — for key types and algorithm constants).

---

## Motivation

EDHOC fills the gap between "I have two parties with credentials" and
"I have a shared OSCORE security context for protecting CoAP traffic."
It is the IoT equivalent of TLS's handshake layer, but:

- **Tiny messages** — 3 messages totaling ~150 bytes for the full
  handshake (vs TLS 1.3's ~2000+ bytes).
- **CBOR-native** — messages are CBOR byte strings and sequences,
  fitting naturally into constrained protocol stacks.
- **COSE-integrated** — uses COSE_Key for credentials, COSE algorithm
  IDs for negotiation, and the same HKDF/AEAD constructions.
- **Designed for OSCORE** — the output is directly usable as an OSCORE
  security context (RFC 8613).

Use cases:

- **IoT device commissioning** — device and cloud establish a shared
  secret during onboarding.
- **Matter / Thread networks** — node-to-node key establishment.
- **Constrained DTLS replacement** — EDHOC + OSCORE achieves the same
  security properties as DTLS with far fewer bytes and round-trips.
- **ACE-OAuth key establishment** — the ACE framework (RFC 9200) can
  use EDHOC for proof-of-possession key exchange.

A Go EDHOC module over corecbor/cose enables server-side IoT platforms
to speak the same key-exchange protocol as constrained devices without
pulling in large TLS-alternative stacks.

---

## Proposal

### Module structure

```
github.com/jahkeup/corecbor/edhoc/    # go.mod: module github.com/jahkeup/corecbor/edhoc
├── doc.go                            # Package doc
├── initiator.go                      # Initiator (Party U) state machine
├── responder.go                      # Responder (Party V) state machine
├── message.go                        # Message 1/2/3/4 types + encode/decode
├── credential.go                     # Credential types (by-value, by-reference)
├── keyschedule.go                    # EDHOC key schedule (Extract/Expand)
├── context.go                        # OSCORE security context derivation
├── ciphersuite.go                    # Cipher suite definitions
├── edhoc_test.go                     # RFC 9528 test vectors
├── initiator_test.go
├── responder_test.go
└── testdata/
    └── rfc9528-vectors/              # Vendored test vectors
```

### Dependency graph

```
github.com/jahkeup/corecbor/edhoc
    │
    ├── github.com/jahkeup/corecbor/cose   (Key types, Algorithm constants)
    ├── github.com/jahkeup/corecbor/cbor   (Value types, encode/decode)
    ├── github.com/jahkeup/corecbor/rfc8949 (CBOR encoding)
    ├── crypto/ecdh                         (X25519, P-256 DH)
    ├── crypto/ed25519                      (signature method 0)
    ├── crypto/ecdsa                        (signature method 2/3)
    ├── crypto/hkdf                         (key schedule)
    ├── crypto/sha256                       (hash)
    ├── crypto/aes + crypto/cipher          (AEAD: AES-CCM-16-64-128)
    └── crypto/hmac                         (MAC method)
```

No non-stdlib, non-corecbor dependencies.

### Public API surface

```go
package edhoc

import (
    "github.com/jahkeup/corecbor/cose"
)

// ---- Cipher Suites (RFC 9528 §3.6) ----

// CipherSuite defines the combination of algorithms for an EDHOC session.
type CipherSuite int64

const (
    // Suite 0: AES-CCM-16-64-128, SHA-256, X25519, EdDSA, AES-CCM-16-64-128, SHA-256
    Suite0 CipherSuite = 0
    // Suite 1: AES-CCM-16-128-128, SHA-256, X25519, EdDSA, AES-CCM-16-64-128, SHA-256
    Suite1 CipherSuite = 1
    // Suite 2: AES-CCM-16-64-128, SHA-256, P-256, ES256, AES-CCM-16-64-128, SHA-256
    Suite2 CipherSuite = 2
    // Suite 3: AES-CCM-16-128-128, SHA-256, P-256, ES256, AES-CCM-16-64-128, SHA-256
    Suite3 CipherSuite = 3
    // Suite 24: ChaCha20/Poly1305, SHA-256, X25519, EdDSA, ChaCha20/Poly1305, SHA-256
    Suite24 CipherSuite = 24
    // Suite 25: ChaCha20/Poly1305, SHA-256, P-256, ES256, ChaCha20/Poly1305, SHA-256
    Suite25 CipherSuite = 25
)

// ---- Credentials ----

// Credential represents an authentication credential for EDHOC.
// It can be a COSE_Key, an X.509 certificate, or a CWT.
type Credential struct {
    // Type indicates the credential type.
    Type CredentialType
    // Key is the COSE_Key (for RPK credentials).
    Key *cose.Key
    // Raw is the raw credential bytes (for certificate/CWT credentials).
    Raw []byte
}

type CredentialType int

const (
    CredentialRPK  CredentialType = iota // Raw Public Key (COSE_Key)
    CredentialX509                       // X.509 certificate
    CredentialCWT                        // CWT with cnf claim
)

// ---- Initiator (Party U) ----

// Initiator drives the EDHOC handshake from the initiator side.
type Initiator struct {
    // unexported state
}

// InitiatorConfig configures an EDHOC initiator session.
type InitiatorConfig struct {
    // Suite is the preferred cipher suite (or list for negotiation).
    Suite CipherSuite
    // Credential is our authentication credential.
    Credential Credential
    // PrivateKey is the long-term authentication key.
    PrivateKey crypto.Signer
    // PeerCredentials is the set of acceptable peer credentials.
    // The CredentialFetcher is called if the peer's credential is
    // referenced but not in this set.
    PeerCredentials []Credential
    // CredentialFetcher resolves credential references (kid, x5t, etc.)
    // to full credentials.  Optional; if nil, only PeerCredentials is used.
    CredentialFetcher func(ref []byte) (*Credential, error)
    // ConnectionID is our connection identifier (C_I).
    // If nil, a random ID is generated.
    ConnectionID []byte
    // ExternalAuthData is application-specific data to authenticate.
    ExternalAuthData []byte
}

// NewInitiator creates a new EDHOC initiator.
func NewInitiator(cfg InitiatorConfig) (*Initiator, error)

// CreateMessage1 generates EDHOC message_1.
func (i *Initiator) CreateMessage1() ([]byte, error)

// ProcessMessage2 processes EDHOC message_2 from the responder.
// Returns message_3 to send.
func (i *Initiator) ProcessMessage2(msg2 []byte) (msg3 []byte, err error)

// ProcessMessage4 processes the optional EDHOC message_4.
// Only needed when the responder sends message_4 for key confirmation.
func (i *Initiator) ProcessMessage4(msg4 []byte) error

// ExportOSCORE derives an OSCORE security context from the completed
// handshake.  Must be called after ProcessMessage2 succeeds.
func (i *Initiator) ExportOSCORE() (*OSCOREContext, error)

// Export derives keying material using the EDHOC Exporter (RFC 9528 §4.2).
func (i *Initiator) Export(label int, context []byte, length int) ([]byte, error)

// ---- Responder (Party V) ----

// Responder drives the EDHOC handshake from the responder side.
type Responder struct {
    // unexported state
}

// ResponderConfig configures an EDHOC responder session.
type ResponderConfig struct {
    Suite            CipherSuite
    Credential       Credential
    PrivateKey       crypto.Signer
    PeerCredentials  []Credential
    CredentialFetcher func(ref []byte) (*Credential, error)
    ConnectionID     []byte
    ExternalAuthData []byte
}

// NewResponder creates a new EDHOC responder.
func NewResponder(cfg ResponderConfig) (*Responder, error)

// ProcessMessage1 processes EDHOC message_1 from the initiator.
// Returns message_2 to send.
func (r *Responder) ProcessMessage1(msg1 []byte) (msg2 []byte, err error)

// ProcessMessage3 processes EDHOC message_3 from the initiator.
// Optionally returns message_4 for explicit key confirmation.
func (r *Responder) ProcessMessage3(msg3 []byte) (msg4 []byte, err error)

// ExportOSCORE derives an OSCORE security context.
// Must be called after ProcessMessage3 succeeds.
func (r *Responder) ExportOSCORE() (*OSCOREContext, error)

// Export derives keying material using the EDHOC Exporter.
func (r *Responder) Export(label int, context []byte, length int) ([]byte, error)

// ---- OSCORE Context (the handshake output) ----

// OSCOREContext contains the derived keying material for OSCORE.
type OSCOREContext struct {
    // MasterSecret is the OSCORE Master Secret.
    MasterSecret []byte
    // MasterSalt is the OSCORE Master Salt.
    MasterSalt []byte
    // SenderID is our OSCORE Sender ID.
    SenderID []byte
    // RecipientID is the peer's OSCORE Sender ID.
    RecipientID []byte
}

// ---- Errors ----

var (
    ErrUnsupportedSuite = errors.New("edhoc: unsupported cipher suite")
    ErrPeerCredential   = errors.New("edhoc: could not resolve peer credential")
    ErrAuthentication   = errors.New("edhoc: peer authentication failed")
    ErrMessageFormat    = errors.New("edhoc: malformed message")
    ErrStateViolation   = errors.New("edhoc: method called in wrong state")
    ErrKeySchedule      = errors.New("edhoc: key schedule derivation failed")
)
```

### Behavior

EDHOC is a 3-message (optionally 4) authenticated key exchange:

```
Initiator (U)                           Responder (V)
    |                                       |
    |-- message_1 (suite, G_X, C_I) ------>|
    |                                       |
    |<-- message_2 (G_Y, C_R, CIPHERTEXT) -|
    |                                       |
    |-- message_3 (CIPHERTEXT) ----------->|
    |                                       |
    |   [optional message_4 for conf.]      |
    |                                       |
    ===== OSCORE context established =======
```

Each message is a CBOR sequence (concatenated CBOR data items, not a
CBOR array).  The ciphertext fields contain COSE_Encrypt0-style
constructions (AEAD-protected credentials + signatures/MACs).

The key schedule is HKDF-based:
- Extract: `PRK = HKDF-Extract(salt, IKM)` where IKM is the ECDH shared secret.
- Expand: derived keys for AEAD, key confirmation, OSCORE export.

All crypto operations use stdlib: `crypto/ecdh` for DH, `crypto/hkdf`
for derivation, `crypto/ed25519` or `crypto/ecdsa` for signatures,
`crypto/aes`+`cipher` for AEAD.

### State machine

The Initiator and Responder maintain internal state:

```
Initiator: Init → Message1Sent → Message2Processed → Complete
Responder: Init → Message1Processed → Message3Processed → Complete
```

Methods called out of order return `ErrStateViolation`.  The state
machine is not exported — callers interact via the sequential method
calls.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| RFC 9528 test vectors (all cipher suites with published vectors) | `TestRFC9528Vectors` table-driven per suite | Yes |
| Full handshake round-trip (Suite 0, X25519+EdDSA) | `TestHandshake_Suite0`: initiator+responder in same process, verify OSCORE context matches | Yes |
| Full handshake round-trip (Suite 2, P-256+ES256) | `TestHandshake_Suite2` | Yes |
| OSCORE context derivation matches expected values | `TestExportOSCORE_MatchesVector` | Yes |
| Exporter produces correct keying material | `TestExport_MatchesVector` | Yes |
| Malformed message_1 → ErrMessageFormat | Negative test | Yes |
| Authentication failure (wrong credential) → ErrAuthentication | Negative test | Yes |
| State violation (ProcessMessage2 before CreateMessage1) → ErrStateViolation | Negative test | Yes |
| Suite negotiation (initiator proposes suite list) | `TestSuiteNegotiation` | Yes |
| Credential by reference (fetcher callback invoked) | `TestCredentialFetcher` | Yes |
| No non-stdlib/non-corecbor deps | `go mod graph` | Yes |
| FuzzProcessMessage1 (arbitrary bytes → no panic) | 30s fuzz | Yes |
| FuzzProcessMessage2 (arbitrary bytes → no panic) | 30s fuzz | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| A | Initiator + Responder for Suite 0 (X25519+EdDSA) + RPK credentials + OSCORE export | Pending | RFC 9528 test vectors pass; handshake round-trips |
| B | Suite 2 (P-256+ES256) + X.509 credentials + suite negotiation | Pending | P-256 vectors pass; suite list negotiation works |
| C | Optional message_4 + CWT credentials + Exporter API | Pending | Full RFC 9528 compliance |

Phase A is independently shippable — Suite 0 (X25519+EdDSA) is the
mandatory-to-implement suite and covers the majority of IoT deployments.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestRFC9528Vectors` | Official test vectors per suite | `edhoc_test.go` |
| `TestHandshake_Suite0` | E2E round-trip | `initiator_test.go` + `responder_test.go` |
| `TestHandshake_Suite2` | P-256 round-trip | same |
| `TestExportOSCORE_*` | Key derivation correctness | `context_test.go` |
| `TestExport_*` | Exporter correctness | `context_test.go` |
| `TestKeySchedule_*` | HKDF Extract/Expand per vector | `keyschedule_test.go` |
| `TestSuiteNegotiation` | Multi-suite proposal handling | `edhoc_test.go` |
| `TestCredentialFetcher` | By-reference resolution | `credential_test.go` |
| `FuzzProcessMessage1` | Adversarial input → no panic | `edhoc_test.go` |
| `FuzzProcessMessage2` | Same | `edhoc_test.go` |
| `FuzzProcessMessage3` | Same | `edhoc_test.go` |

---

## Performance

| Metric | Target | Test mechanism |
|---|---|---|
| Full handshake (Suite 0, X25519+EdDSA) | ≤ 1ms total (both sides) | `BenchmarkHandshake_Suite0` |
| Full handshake (Suite 2, P-256+ES256) | ≤ 5ms total | `BenchmarkHandshake_Suite2` |
| Message encode/decode | ≤ 2 allocations per message | `-benchmem` |

Handshake performance is dominated by ECDH and signing — both stdlib
with hardware acceleration on modern platforms.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| RFC 9528 test vectors not yet widely available | medium | medium | Cross-validate against reference implementations (RISE EDHOC C impl, lake-wg test vectors) |
| AES-CCM-16-64-128 required for Suite 0/1/2/3 | high | low | Depends on COSE module's internal/aesccm (proposal 002 Phase C); can share or duplicate |
| ChaCha20-Poly1305 for Suite 24/25 | medium | low | Same constraint as COSE module — defer or accept x/crypto |
| Protocol state machine complexity | medium | medium | Comprehensive state-transition tests; refuse operations in wrong state |
| EDHOC is newer than COSE/CWT (fewer battle-tested implementations) | medium | low | Strict vector-driven testing; fuzz all message parsers |

---

## Alternatives considered

### Use an existing EDHOC Go library

No complete, maintained Go EDHOC implementation exists as of filing.
Partial implementations are either abandoned or coupled to specific
CoAP stacks.

### Implement EDHOC inside the COSE module

Rejected. EDHOC is a protocol with state, not a stateless
encode/sign operation. It deserves its own module with its own
lifecycle, and its dependency on COSE is limited to key types and
algorithm constants.

### Skip EDHOC (use TLS/DTLS instead for key establishment)

Rejected for the target use case. EDHOC's value is specifically for
constrained environments where DTLS is too large.  A Go server-side
EDHOC implementation enables cloud platforms to participate in IoT key
exchange without shipping full DTLS stacks to constrained devices.

---

## Open questions

- **AES-CCM sharing with COSE module**: Should EDHOC import the COSE
  module's `internal/aesccm` package (requires making it non-internal),
  or duplicate the ~200 LOC? Lean: extract to a shared `internal/`
  package at the workspace level, or promote to a small public
  `github.com/jahkeup/corecbor/aesccm` package.

- **OSCORE module**: EDHOC produces an OSCORE context. Should there
  be a separate OSCORE module that consumes this context and
  implements RFC 8613 object security? Lean: yes, but that's a
  separate proposal (it needs CoAP message awareness).

- **Connection ID management**: In real deployments, connection IDs
  need to be tracked and looked up. Should the EDHOC module provide
  a session store interface? Lean: no — that's application layer.
  The module handles single handshakes; multiplexing is the caller's
  concern.

---

## Cross-references

- RFCs: RFC 9528 — EDHOC (primary spec).
- RFCs: RFC 8613 — OSCORE (the consumer of EDHOC's output).
- RFCs: `../rfcs/rfc9052.txt` — COSE (key types, algorithm IDs).
- Sibling proposals: `001` (corecbor), `002` (COSE), `003` (CWT).
- External: lake-wg test vectors:
  https://github.com/lake-wg/edhoc — reference vectors.
- External: RISE EDHOC C implementation:
  https://github.com/openwsn-berkeley/EDHOC-C — cross-validation.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-05-20 | Initial draft | corecbor maintainers |
