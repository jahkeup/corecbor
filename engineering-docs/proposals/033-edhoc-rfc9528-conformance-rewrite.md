# 033 — EDHOC: RFC 9528 conformance rewrite

## Header

| Field | Value |
|---|---|
| **Number** | 033 |
| **Tier** | 3 |
| **Status** | Closed |
| **Filed** | 2026-11-20 |
| **Owner** | corecbor maintainers |
| **Depends on** | proposals: 004 (EDHOC), 022 (raw-byte preservation), 028 (COSE key API: `ParseKey`, ID_CRED header parsing), 031 (CWT hardening — CCS/CWT credential validation), 034 (compatibility policy) |
| **Supersedes** | proposals: 004 (protocol core; 004's module layout and API sketch remain the starting point) |
| **Spec sections touched** | none — sibling module `edhoc/` |

---

## TL;DR

Proposal 004 is marked Closed, but the `edhoc` module implements an
early draft of EDHOC, not RFC 9528. Most of the protocol is wrong:

- the key-derivation function's input format
- the transcript hashes
- the PRK extraction salt
- how message_2 is built and encrypted
- the MAC and signature inputs
- the AEAD associated data
- cipher-suite selection
- connection-ID encoding
- the P-256 public-key format

It can't complete a handshake with any other EDHOC implementation, and
the OSCORE context it exports doesn't match RFC 9528 Appendix A.1. The
gating criterion of 004, "RFC 9528 test vectors", was never met:
nothing in `edhoc/` references RFC 9529.

This proposal rewrites the protocol core against RFC 9528 and gates it
on the **RFC 9529 traces** as golden tests. Per proposal 034 the
exported Go API stays stable: the internals are rewritten behind the
existing identifiers (a Contract defect fix — the package documents RFC
9528), and new capability is added beside them. It also fixes the credential
and state-machine safety gaps, and adds the RFC 9668 CoAP/OSCORE
transport helpers.

Until it closes, `edhoc/doc.go` and the README MUST label the module
**experimental / non-interoperable**.

Acceptance:

- Every RFC 9529 trace reproduces byte-for-byte, including
  intermediate values: TH_2, PRK_2e, KEYSTREAM_2, MAC_2, PRK_out,
  and the OSCORE Master Secret and Salt.
- A full handshake against the traces' fixed ephemeral keys succeeds in
  both roles.

---

## Motivation

The review of `main@00e1307` (2026-11-20) found the following. Every
row was confirmed by reading the source. The RFC column paraphrases
RFC 9528 and MUST be checked against the vendored text when this
proposal is implemented (see the acceptance criteria).

| # | Area | Code | RFC 9528 | Evidence |
|---|---|---|---|---|
| 1 | EDHOC_KDF `info` | CBOR **array** `[TH bstr, label tstr, length]` | CBOR **sequence** `(info_label: int, context: bstr, length: uint)` with integer labels (§4.1.2) | `edhoc/keyschedule.go:59-76` |
| 2 | TH_2 | `SHA-256(message_1_raw ‖ bstr(G_Y) ‖ C_R)`. The comment says `H(message_1)` but the code hashes the raw bytes. | `H(G_Y, H(message_1))`, where each is a bstr in a CBOR sequence (§5.3.2) | `edhoc/keyschedule.go:20-31` |
| 3 | TH_3 / TH_4 | `H(TH_x, CIPHERTEXT_x)` | `H(TH_2, PLAINTEXT_2, CRED_R)` / `H(TH_3, PLAINTEXT_3, CRED_I)` (§5.3.3, §5.4.3) | `edhoc/keyschedule.go:33-51`; `edhoc/initiator.go:155,162`; `edhoc/responder.go:141,256` |
| 4 | PRK_2e | `HKDF-Extract(salt = nil, G_XY)` | `EDHOC_Extract(salt = TH_2, IKM = G_XY)` (§4.1.1.1) | `edhoc/keyschedule.go:53-57` |
| 5 | message_2 | Three sequence items `(G_Y, C_R, CIPHERTEXT_2)`. CIPHERTEXT_2 is an **AEAD** seal under K_2e / IV_2e. | One bstr `G_Y_CIPHERTEXT_2`. CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2. C_R moves **inside** PLAINTEXT_2 (§5.3) | `edhoc/message.go:144-194`; `edhoc/responder.go:162-216`; `edhoc/initiator.go:211-236` |
| 6 | MAC_2 / MAC_3 input | `EDHOC_KDF(PRK, TH, "MAC_x", AEADTagSize)`. Context is TH only. | `context_2 = <<C_R, ID_CRED_R, TH_2, CRED_R, ? EAD_2>>`, `context_3 = <<ID_CRED_I, TH_3, CRED_I, ? EAD_3>>`. With signature authentication, `mac_length = hash_length`, not the tag length (§5.3.2, §5.4.2). | `edhoc/initiator.go:254,303`; `edhoc/responder.go:174,308` |
| 7 | Signature input | `["Signature1", ID_CRED, TH, MAC]`. **CRED_x and EAD are absent**, so the signature doesn't bind the credential (identity misbinding). | COSE Sig_structure `["Signature1", <<ID_CRED_x>>, <<TH_x, CRED_x, ? EAD_x>>, MAC_x]` | `edhoc/initiator.go:347-354` |
| 8 | AEAD associated data (msg 3 / msg 4) | `[TH]` (array) | COSE Enc_structure `["Encrypt0", h'', TH_x]` (§5.4.2, §5.5.2) | `edhoc/initiator.go:199,339`; `edhoc/responder.go:242,282` |
| 9 | Suite selection | `SUITES_I[0]` is treated as the selected suite | The **last** element of a `SUITES_I` array is the selected suite (§5.2.2) | `edhoc/message.go:98`; `edhoc/initiator.go:64` |
| 10 | Responder negotiation | Picks the first mutually supported suite and ignores the initiator's selection. A mismatch is never reported. | If the selected suite isn't supported, reply with an error message (ERR_CODE 2, `SUITES_R`) (§6.3) | `edhoc/responder.go:101-107,151-160` |
| 11 | P-256 G_X / G_Y | `ecdh.PublicKey.Bytes()`, i.e. the 65-byte uncompressed point | x-coordinate only (32 bytes) (§5.2.1 / §3.7) | `edhoc/initiator.go:106`; `edhoc/responder.go:145` |
| 12 | Connection IDs | Only bytes 0x00–0x17 become ints. 0x20–0x37 (negative ints −1…−24) are sent as bstr. On decode, negative ints are rejected and uints > 255 are truncated by `byte(...)`. | A one-byte bstr whose byte is a valid single-byte CBOR int encoding MUST be sent as that int (§3.3.2) | `edhoc/message.go:219-241` |
| 13 | C_I ≠ C_R | Not enforced. The default IDs are random in 0..23, so they collide with probability 1/24. | Must differ, because each serves as the peer's OSCORE Recipient ID (§3.3.3, App. A.1) | `edhoc/initiator.go:72-79`; `edhoc/responder.go:71-78` |
| 14 | Exporter / OSCORE | Text labels `"OSCORE_Master_Secret"` / `"OSCORE_Master_Salt"` derived straight from PRK_4e3m. `Export` uses `"EDHOC_Exporter_%d"`. | `PRK_out = EDHOC_KDF(PRK_4e3m, 7, TH_4, hash_length)`; `PRK_exporter = EDHOC_KDF(PRK_out, 10, h'', hash_length)`; `EDHOC_Exporter(label, ctx, len) = EDHOC_KDF(PRK_exporter, label, ctx, len)`. Master Secret = `Exporter(0, h'', key_len)`, Master Salt = `Exporter(1, h'', 8)` (§4.2, App. A.1) | `edhoc/context.go:15-82`; `edhoc/keyschedule.go:78-85` |
| 15 | OSCORE IDs | `SenderID` = **own** connection ID, `RecipientID` = peer's | Each party's **Recipient** ID is the connection ID it chose itself. Initiator: Sender = C_R, Recipient = C_I (App. A.1) | `edhoc/context.go:54-59,76-81` |
| 16 | ID_CRED | RPK sent as `{4: raw_pubkey}` (kid misused to carry key material). Received ID_CRED is ignored for key lookup. Compact kid encoding is unsupported. | ID_CRED is a COSE header map (kid 4, x5chain 33, x5t 34, kccs 14, kcwt 13). A kid-only map is sent compactly as the bare kid (§3.5.3) | `edhoc/initiator.go:356-365`; `:268-283` |
| 17 | Peer key requirement | `NewInitiator` / `NewResponder` require `PeerPublic`, so a responder can't serve initiators it doesn't know in advance | Credential is resolved from ID_CRED (§3.5) | `edhoc/initiator.go:68`; `edhoc/responder.go:67` |
| 18 | CWT credentials | `cwt.Verify` checks the signature only, with no time checks. If `CWTIssuerKey` is nil it **falls back to `PeerPublic` as the issuer key**. | Validate credentials per the application profile (§3.5.2, §9) | `edhoc/credential.go:37-73`; `edhoc/initiator.go:275-278`; `edhoc/responder.go:329-332` |
| 19 | EC2 keys from CWT | Built from raw `big.Int` with **no on-curve check** | — (basic hygiene) | `edhoc/credential.go:211-216` |
| 20 | Failure handling | On failure the state isn't advanced and there's no terminal state. `ProcessMessage2` / `ProcessMessage3` can be retried with the same ephemeral key and PRKs. | Abort on error. Discard the session (§5) | `edhoc/initiator.go:119-166`; `edhoc/responder.go:218-259` |
| 21 | Secret hygiene | `ephPriv`, PRKs and THs are never zeroed | Implementation considerations (`draft-ietf-lake-edhoc-impl-cons`) | `edhoc/initiator.go:39-58`; `edhoc/responder.go:35-56` |
| 22 | EAD / errors | EAD_1 is dropped (`decodeMessage1` ignores trailing items). No error message type. No EAD at all. | EAD items (§3.8); error messages (§6) | `edhoc/message.go:136` |
| 23 | Suite / signature binding | The signature algorithm is chosen by key type, not by suite (Suite 0 = EdDSA, Suite 2 = ES256). Unknown suites fall back to Suite 0 parameters. | Suite fixes the signature algorithm (§3.6) | `edhoc/initiator.go:391-436`; `edhoc/ciphersuite.go:35-54` |
| 24 | Signer support | `computeSignature` type-asserts `ed25519.PrivateKey` / `*ecdsa.PrivateKey`, so HSM / KMS `crypto.Signer`s fail | — | `edhoc/initiator.go:391-412` |

One thing the code gets **right**: `PRK_3e2m = PRK_4e3m = PRK_2e` is
correct for method 0 (signature/signature), where neither party
authenticates with a static DH key (§4.1.1.2–3). The rewrite keeps that
derivation and adds the method 1–3 branches behind an explicit method
switch.

### Consumers

- **OSCORE stacks over CoAP (RFC 9668, RFC 8613).** They need a correct
  Master Secret / Salt / Sender ID / Recipient ID, and the combined
  EDHOC + OSCORE request.
- **ACE EDHOC-OSCORE profile (`draft-ietf-ace-edhoc-oscore-profile`).**
  It needs CWT/CCS credentials resolved by `kid`.
- **Remote attestation over EDHOC (`draft-ietf-lake-ra`).** It needs
  EAD items and pairs with proposal 032.
- **Interop with any other EDHOC stack** (lakers, uoscore-uedhoc,
  aiocoap). Today this is impossible.

---

## Proposal

### Module status

Immediately, before any code changes:

- `edhoc/doc.go` gets an "Experimental: does not yet conform to RFC
  9528; see proposal 033" paragraph.
- The README layout row is updated the same way.
- Proposal 004 is marked **Superseded** (by 033), with a note that its
  gating vector criterion was not met. Done 2026-11-20.

### Key schedule (internal)

```go
// kdfLabel enumerates EDHOC_KDF info_label values (RFC 9528 §4.1.2).
type kdfLabel int64

const (
	labelKeystream2  kdfLabel = 0
	labelSalt3e2m    kdfLabel = 1
	labelMAC2        kdfLabel = 2
	labelK3          kdfLabel = 3
	labelIV3         kdfLabel = 4
	labelSalt4e3m    kdfLabel = 5
	labelMAC3        kdfLabel = 6
	labelPRKOut      kdfLabel = 7
	labelK4          kdfLabel = 8
	labelIV4         kdfLabel = 9
	labelPRKExporter kdfLabel = 10
	labelKeyUpdate   kdfLabel = 11
)

// kdf computes EDHOC_KDF(prk, label, context, length): HKDF-Expand
// with info = CBOR sequence (label int, context bstr, length uint).
func (s *suite) kdf(prk []byte, label kdfLabel, context []byte, length int) ([]byte, error)

// th computes H(items...) where each item is already CBOR-encoded.
func (s *suite) th(items ...[]byte) []byte
```

The hash comes from the suite instead of a fixed `sha256.New`. That is
needed for suites 4–6 (SHA-256) versus 24 / 25 (SHA-384 / SHAKE256),
which aren't in scope but shouldn't be ruled out by the design. HKDF
moves to stdlib `crypto/hkdf` (Go ≥ 1.24), which drops the
`golang.org/x/crypto` dependency and meets 004's "no non-stdlib deps"
criterion.

### Public API surface

Per proposal 034, every v0.2.2 exported identifier keeps its name and
signature: `InitiatorConfig`/`ResponderConfig` keep all their fields with
their types, `Credential` keeps `Type` and `CWTBytes`, `OSCOREContext`
keeps its four fields, and `CreateMessage1`, `ProcessMessage1..4`,
`CreateMessage4`, `Export` and `ExportOSCORE` keep their signatures. The
package documents RFC 9528 (`edhoc/doc.go:4-5`), so what those
identifiers *compute* is a Contract defect and is fixed in place. New
capability is added beside them.

```go
type Method int

const (
	MethodSigSig   Method = 0 // supported
	MethodSigStat  Method = 1 // Phase D
	MethodStatSig  Method = 2 // Phase D
	MethodStatStat Method = 3 // Phase D
)

// Credential keeps its v0.2.2 fields; new fields are appended.
type Credential struct {
	Type     CredentialType // unchanged (CredentialRPK, CredentialCWT)
	CWTBytes []byte         // unchanged

	// --- new in v0.3 ---
	// Raw is CRED_x exactly as it enters the transcript (TH_3 / TH_4,
	// MAC context, Sig_structure). For a CCS this is the encoded
	// claims set; for X.509 the DER certificate; for a CWT the token.
	// When empty, it is derived from Type/CWTBytes/the public key.
	Raw       []byte
	IDCred    IDCred           // how we refer to it on the wire
	PublicKey crypto.PublicKey // authentication key bound by Raw
}

// IDCred is a parsed ID_CRED_x (RFC 9528 §3.5.3). Exactly one field
// is set. KID uses the compact encoding on the wire when it is the
// only parameter.
type IDCred struct {
	KID     []byte
	X5T     *cose.X5T    // label 34 (RFC 9360)
	X5Chain [][]byte     // label 33
	KCCS    []byte       // label 14: CCS by value
	KCWT    []byte       // label 13: CWT by value
}

func ParseIDCred(v corecbor.Value) (IDCred, error)

// CredentialResolver maps a received ID_CRED to a credential the
// application trusts. It MUST perform the profile's validation
// (expiry, issuer, revocation) — EDHOC does not.
type CredentialResolver interface {
	ResolveCredential(ctx context.Context, id IDCred) (*Credential, error)
}

// EADItem is an External Authorization Data item (§3.8). A negative
// label on the wire marks the item critical.
type EADItem struct {
	Label    uint64
	Critical bool
	Value    []byte // nil when absent
}

// NewInitiator / NewResponder gain an appended ...Option. With no
// options they run RFC 9528 (the contract-defect fix); there is no
// other no-option behavior change.
func NewInitiator(cfg InitiatorConfig, opts ...Option) (*Initiator, error)
func NewResponder(cfg ResponderConfig, opts ...Option) (*Responder, error) // ResponderConfig mirrors InitiatorConfig

type Option func(*options)

// WithLegacyPreRFCProtocol runs the pre-RFC key schedule, message
// layout and OSCORE export that corecbor <= v0.2 implemented. It
// interoperates ONLY with peers running corecbor <= v0.2 and gives none
// of RFC 9528's credential-binding guarantees (see Motivation). It
// exists so deployed v0.2 fleets can upgrade both ends in stages. The
// v0.2 config fields (PeerPublic, PeerCredential, CWTIssuerKey) are
// used exactly as v0.2.2 used them.
//
// Deprecated: non-interoperable and missing identity binding. Removed
// no earlier than v0.5.0. Not part of any CompatV02 bundle.
func WithLegacyPreRFCProtocol() Option

// InitiatorConfig keeps every v0.2.2 field with its type; new fields
// are appended and their zero values select the v0.2.2 credential
// model (a pinned PeerPublic).
type InitiatorConfig struct {
	Suites       []CipherSuite    // unchanged; preference order, last = selected (encoded per §5.2.2)
	PrivateKey   crypto.Signer    // unchanged; any crypto.Signer (KMS / HSM); suite/key mismatch rejected at construction
	PeerPublic   crypto.PublicKey // unchanged; when Peers is nil, the pinned peer RPK
	ConnectionID []byte           // unchanged; nil: random, guaranteed != peer's after msg 2

	Credential     *Credential      // unchanged
	PeerCredential *Credential      // unchanged; pinned peer credential when Peers is nil
	CWTIssuerKey   crypto.PublicKey // unchanged; no longer falls back to PeerPublic (Safety defect)

	// --- new in v0.3 ---
	Method     Method
	Peers      CredentialResolver // when set, takes precedence over PeerPublic/PeerCredential
	EAD1, EAD3 []EADItem
	// Rand overrides crypto/rand for deterministic tests (RFC 9529).
	Rand io.Reader
}

// ConnectionID is a C_I / C_R value. Constructors enforce the §3.3.2
// encoding rules. It is a helper type; config fields stay []byte.
type ConnectionID []byte

func ConnectionIDFromInt(n int8) (ConnectionID, error) // -24..23

// ErrorMessage is an EDHOC error message (§6). It implements error.
type ErrorMessage struct {
	Code    int64           // 1: unspecified, 2: wrong selected suite
	Info    string          // ERR_CODE 1
	SuitesR []CipherSuite   // ERR_CODE 2
}

func (e *ErrorMessage) Error() string
func (e *ErrorMessage) MarshalCBOR() ([]byte, error)

// Existing Initiator methods keep their v0.2.2 signatures.
func (i *Initiator) CreateMessage1() ([]byte, error)
func (i *Initiator) ProcessMessage2(msg2 []byte) (msg3 []byte, err error) // resolver called with context.Background()
func (i *Initiator) ProcessMessage4(msg4 []byte) error
func (i *Initiator) Export(label int, context []byte, length int) ([]byte, error) // now RFC 9528 §4.2.1 EDHOC_Exporter
func (i *Initiator) ExportOSCORE() (*OSCOREContext, error)                        // now RFC 9528 Appendix A.1

// New Initiator methods.
func (i *Initiator) ProcessMessage2Context(ctx context.Context, msg2 []byte) (msg3 []byte, err error)
func (i *Initiator) PeerEAD() []EADItem
func (i *Initiator) PeerCredential() *Credential
func (i *Initiator) PRKOut() ([]byte, error)
func (i *Initiator) KeyUpdate(context []byte) error // §H, labelKeyUpdate
func (i *Initiator) OSCORE(params OSCOREParams) (*OSCOREContext, error)
func (i *Initiator) Close() // zeroizes ephemeral key, PRKs, THs; idempotent

type OSCOREParams struct {
	AEAD      cose.Algorithm // default AES-CCM-16-64-128 (10)
	HKDF      cose.Algorithm // default HKDF-SHA-256 (-10)
	SaltLen   int            // default 8
}

// OSCOREContext keeps its v0.2.2 fields; two are appended.
type OSCOREContext struct {
	MasterSecret []byte
	MasterSalt   []byte
	SenderID     []byte // the PEER's connection ID (v0.2.2 had these swapped)
	RecipientID  []byte // OUR connection ID
	AEAD         cose.Algorithm // new
	HKDF         cose.Algorithm // new
}
```

The responder mirrors this: the existing `ProcessMessage1`,
`ProcessMessage3`, `CreateMessage4`, `Export`, `ExportOSCORE` keep their
signatures, and `ProcessMessage3Context`, `PeerEAD`, `PeerCredential`,
`PRKOut`, `KeyUpdate`, `OSCORE`, `Close` are added. `ProcessMessage1` returns
`*ErrorMessage` as the error when the selected suite isn't supported.
The caller sends `errMsg.MarshalCBOR()` to the peer.

`ctx` exists only for `CredentialResolver` calls, through the new
`…Context` methods; the existing methods use `context.Background()`.
The state machine itself stays sans-IO.

### State machine

```
Init ──CreateMessage1──► WaitM2 ──ProcessMessage2──► Completed ──Close──► Closed
  │                         │                          │
  └──────── any error ──────┴──────────────────────────┴──► Failed (terminal)
```

Rules:

- Any error moves the session to `Failed`, and every later call returns
  `ErrStateViolation`.
- Entering `Failed` or `Closed` zeroizes secrets.
- `Export`, `ExportOSCORE`, `OSCORE` and `PRKOut` are valid only in `Completed` (as `Export`/`ExportOSCORE` already were in v0.2.2).
- On the responder, `Completed` means after message_3, or after
  message_4 when the application profile requires it.

### Transport helpers (RFC 9668)

```go
package edhoc // or edhoc/coap if it grows

// CoAPMessage1 prefixes message_1 with CBOR true, as required when
// carried in a CoAP request to the EDHOC resource (RFC 9668 §3).
func CoAPMessage1(msg1 []byte) []byte

// CoAPMessageWithCR prefixes message_3 (or an error) with C_R for
// responder-side dispatch.
func CoAPMessageWithCR(cR ConnectionID, msg []byte) []byte

// SplitCoAPPrefix parses the prefix and returns (cR or nil, isMsg1, rest).
func SplitCoAPPrefix(payload []byte) (ConnectionID, bool, []byte, error)

// The combined EDHOC+OSCORE request (RFC 9668 §3) is out of scope for
// the edhoc module; it is an OSCORE-layer concern. Document the
// integration point instead.
```

### Failure modes

The existing sentinels stay: `ErrAuthentication`, `ErrMessageFormat`,
`ErrStateViolation`, `ErrUnsupportedSuite`.

New sentinels:

- `ErrConnectionIDCollision`
- `ErrCredentialRejected`, wrapping the resolver's error
- `ErrCriticalEAD`, for an unsupported critical EAD item

`*ErrorMessage` is returned for protocol-level errors that the peer
must be told about. Every wrap uses `%w`. The current
`fmt.Errorf("%w: ...: %v", ...)` pattern (e.g. `edhoc/initiator.go:132`,
`edhoc/credential.go:45`) is replaced.

---

## Implementation notes (protocol core, 2026-11-21)

**Gate met.** Both RFC 9529 traces reproduce byte-for-byte
(`edhoc/rfc9529_test.go`, which parses the vendored
`engineering-docs/rfcs/rfc9529.txt` directly): message_1–4, TH_2/3/4,
G_XY, PRK_2e/3e2m/4e3m, context_2/3, MAC_2/3, Signature_or_MAC_2/3,
PLAINTEXT_2/3, KEYSTREAM_2, CIPHERTEXT_2/3, A_3/A_4, K_3/IV_3, K_4/IV_4,
PRK_out, PRK_exporter, OSCORE Master Secret/Salt and Sender IDs, and the
KeyUpdate outputs.

- Trace 1 (§2): method 0, suite 0, x5t — full handshake in both roles.
- Trace 2 (§3): method 3, suite 2, kid + CCS, including the ERR_CODE 2
  round. **RFC inconsistency:** the rejected first message_1 (§3.1)
  selects suite 6 (X25519) but carries a P-256 G_X. Our X25519 key is
  right for suite 6; the test compares that message with G_X masked and
  feeds the RFC's own bytes to the Responder.

**Scope delivered beyond the Phase plan:** all four methods (static DH
needs `DHKey`, or an `*ecdsa.PrivateKey` signer on the suite curve), and
suites 0–6 and 24 (25 needs X448, which neither std nor x/crypto has).

**API as implemented** (additive; apicheck clean with the two appended
`...Option` parameters allowlisted):

- New config fields: `Method`, `DHKey`, `Peers`, `EAD1`/`EAD3`
  (`EAD2`/`EAD4` on the Responder), `AcceptCriticalEAD`, `Rand`, and on
  `ResponderConfig` `AnyMethod` (the zero value still accepts only
  method 0, as v0.2 did).
- `Credential` gains `Raw`, `IDCred`, `PublicKey`. A v0.2-style config
  (signer + `PeerPublic`) derives a CCS `{8: {1: COSE_Key}}` and sends
  it by value (kccs); the peer checks its key against `PeerPublic`.
- `IDCred` (KID, X5T, X5Chain, KCCS, KCWT), `ParseIDCred`, `EADItem`,
  `ConnectionID`/`ConnectionIDFromInt`, `ErrorMessage` (+ `ErrPeerError`,
  `ErrCode*`), `RetrySuites`, `OSCOREParams`, `PRKOut`, `KeyUpdate`,
  `OSCORE`, `Close`, `PeerEAD`, `PeerCredential`,
  `ProcessMessage2Context`/`ProcessMessage3Context`.
- `OSCOREParams` carries `MasterSecretLen`/`MasterSaltLen` instead of the
  sketch's AEAD/HKDF; `OSCOREContext` gains `AEAD` and `HKDF` as
  proposed (HKDF is 0 for SHA-384 suites, which have no registered COSE
  HKDF identifier).
- **Replace when 028 lands:** `edhoc.X5T` is local and
  `coseKeyOf`/`publicFromCOSEKey` (`edhoc/credrfc.go`) are minimal local
  COSE_Key helpers. Both should move to cose's key API; since v0.3 is
  unreleased, swapping `IDCred.X5T` to `*cose.X5T` before release is not
  an API break against v0.2.2.

**Compatibility:**

- `NewInitiator`/`NewResponder` still fail fast with `ErrStateViolation`
  when a party has no key or nothing to authenticate the peer against.
- Error messages match `ErrPeerError`, plus `ErrUnsupportedSuite` for
  ERR_CODE 2 and for an unsupported method (what v0.2 returned).
- `WithLegacyPreRFCProtocol()` reproduces every v0.2.2 golden vector
  with no allowlist (`TestGoldenLegacyReproducesV022`). The default path's
  golden diffs are allowlisted under "proposal 033".
- `Suites` now selects the LAST entry (RFC 9528 §5.2.2), a contract
  defect fix; multi-suite v0.2 configs that relied on "first" need
  reordering (migration guide).

## Implementation notes (follow-ups, 2026-11-21)

- **cose key API (028).** `edhoc.X5T` is an alias of `cose.CertHash`.
  COSE_Key building and parsing use `cose.NewKeyFromPublic`,
  `MarshalCBOR`, `ParseKey` and `(*Key).PublicKey`, so credential keys
  get cose's validation (exact coordinate sizes, on-curve). cose has no
  constructor for X25519 keys (`*ecdh.PublicKey`), so that OKP map is
  built in edhoc and validated with `cose.ParseKey`; P-curve ECDH keys
  go through their ECDSA form. Suggested follow-up for cose:
  `NewKeyFromPublic` accepting `*ecdh.PublicKey`.
- **CWT credentials** read `cnf` only through cwt's typed
  `Confirmation`; the unreachable `ClaimsSet.Private` fallback is gone
  (031 deprecates `Private`).
- **Transport (RFC 9528 Appendix A.2, RFC 9668), `edhoc/coap.go`:**
  `CoAPMessage1`, `CoAPMessageWithCID` (named for both C_R in the
  forward flow and C_I in the reverse flow, instead of the sketch's
  `CoAPMessageWithCR`), `SplitCoAPPrefix` (deterministic prefixes
  only: shortest, definite heads), `CombinedPayload` /
  `SplitCombinedPayload` for the EDHOC + OSCORE request,
  `ConnectionID` / `PeerConnectionID` accessors, and constants (path,
  media types, Content-Formats 64/65, EDHOC option 21). RFC 9668 §3.4
  Figure 4 is a test vector. The OSCORE layer itself stays out of
  scope, as planned.
- **X.509 (`edhoc/x509.go`):** `X509Resolver(X509Policy)` plugs into
  `Peers` and verifies x5chain / x5t (x5t resolved through
  `X509Policy.Certificates`, leaf checked against the hash) with
  `crypto/x509` against required caller-supplied `Roots`;
  `X509Credential` builds a party's own credential. No config changes.
- **Sentinels:** `ErrCredentialRejected`, `ErrConnectionIDCollision`,
  `ErrCriticalEAD`, each wrapped alongside the sentinel the site
  returned before.
- **HKDF** in the legacy key schedule moved to `crypto/hkdf`.

### Acceptance status

All gating criteria are met except one:

| Criterion | Status |
|---|---|
| `golang.org/x/crypto` used only for ChaCha20-Poly1305 (amended 2026-11-22, see below) | **Met.** The only import is `golang.org/x/crypto/chacha20poly1305` for suites 4 and 5; everything else uses the standard library. |
| Interop smoke test against an external implementation | Not done (non-gating). |

Tests for the other rows: `TestRFC9529Trace1/2`, `TestSuiteNegotiation_*`,
`TestRFC_RetrySuites`, `TestRFC_ConnectionIDEncoding`,
`TestConnectionID_Collision`, `TestRFC_OffCurveP256Rejected`,
`TestOSCORE` values in the traces, `TestRFC_FailureIsTerminal`,
`TestRFC_CloseZeroizes`, `TestIDCred_*`, `TestCredential_NoIssuerFallback`,
`TestCredential_OffCurve`, `TestRFC_UnknownCriticalEADAborts` /
`TestEAD_UnknownCritical`, `TestPrivateKey_GenericSigner`,
`TestConfigV022Shape`, `FuzzProcessMessage1–4NeverPanic`,
`TestCompatDefaultRejectsLegacyPeer`, `TestCompatLegacyPreRFCTranscript`
with `TestGoldenLegacyReproducesV022`, `TestLegacySelectorDeprecated`,
apicheck and the golden vectors in `make check`.

**Amended criterion (maintainer decision, 2026-11-22).** The original
row required removing `golang.org/x/crypto` entirely; it was written
when only suites 0 and 2 were planned. Suites 4 and 5 (RFC 9528
ChaCha20-Poly1305) are kept, so `x/crypto` is allowed for
ChaCha20-Poly1305 only, until the standard library provides it.

All gating criteria are met; 033 is Closed and edhoc is no longer
marked experimental.

## Compatibility selection

Classified per [034](034-standards-currency-and-legacy-compatibility.md).
No exported identifier is removed, renamed or retyped (see Public API
surface). The package documents RFC 9528 (`edhoc/doc.go:4-5`), so the
protocol computations behind the existing identifiers are Contract
defects fixed in place.

| Change | Class | Contract restored | Existing identifiers in v0.3 | Selector |
|---|---|---|---|---|
| Key schedule, transcripts, message_2 layout, MAC/Sig/AEAD inputs, suite selection, C_ID encoding, P-256 x-only keys | Contract defect | `edhoc/doc.go:4-5` ("implements the EDHOC authenticated key exchange protocol (RFC 9528)"); RFC 9528 §4, §5 | same methods, RFC 9528 wire format | `func WithLegacyPreRFCProtocol() Option` — Deprecated; whole-protocol switch, never per-field. Not bundled |
| `Export` uses `EDHOC_Exporter`; `ExportOSCORE` follows Appendix A.1 with Sender/Recipient IDs un-swapped | Contract defect | RFC 9528 §4.2.1, Appendix A.1 | same signatures | covered by `WithLegacyPreRFCProtocol()` |
| Unknown cipher suites fail (ERR_CODE 2) instead of falling back to suite 0 | Contract defect | RFC 9528 §6.3 | error message | none (also enforced in legacy mode) |
| `CWTIssuerKey` nil no longer falls back to `PeerPublic`; on-curve checks; C_I ≠ C_R; terminal state after failure; zeroization | Safety defect | — | enforced | none (also enforced in legacy mode) |
| Credential resolution | Additive | — | `PeerPublic`/`PeerCredential` keep pinning the peer when `Peers` is nil | `InitiatorConfig.Peers` / `ResponderConfig.Peers` |
| Context-aware resolution | Additive | — | existing methods use `context.Background()` | `ProcessMessage2Context`, `ProcessMessage3Context` |
| Methods 1–3, EAD, error messages, RFC 9668 helpers, `PRKOut`, `KeyUpdate`, `OSCORE(params)`, `Close` | Additive | — | n/a | n/a |
| LAKE drafts (PSK, app profiles, GREASE, authz, ra, pqsuites, authkem) | Draft | — | not implemented | when implemented before publication: `WithDraft…` selectors naming the draft revision, Experimental, never default |

**No `edhoc.CompatV02` bundle.** The only legacy selector removes RFC
9528's identity binding, so under 027's bundling rule it must be named
explicitly. It is excluded from bundles, as 034's risk table requires.

**Appended `...Option` parameters (apidiff-visible, migration-guide
entries):** `NewInitiator(cfg, opts ...Option)`,
`NewResponder(cfg, opts ...Option)`.

---

## Acceptance criteria

| Criterion | Test mechanism | Gating? |
|---|---|---|
| RFC 9528 and RFC 9529 vendored under `engineering-docs/rfcs/` with inventory rows | file review | Yes |
| RFC 9529 trace(s) for method 0 reproduce every intermediate value (message_1/2/3/4, TH_2..TH_4, PRK_2e, KEYSTREAM_2, MAC_2, MAC_3, PRK_out, PRK_exporter, OSCORE Master Secret/Salt, Sender/Recipient IDs) byte-for-byte, both roles, with fixed ephemeral keys via `Rand` | `TestRFC9529_Trace*` table-driven | Yes |
| Every other RFC 9529 trace either passes or is listed as unsupported (e.g. methods 1–3 until Phase D), each skip naming its trace section | same | Yes |
| Selected suite = last array element; responder returns `*ErrorMessage{Code:2}` with `SUITES_R` when unsupported | `TestSuiteNegotiation_RFC9528` | Yes |
| Connection-ID encoding: bstr `h'20'` ↔ int −1; uint 300 rejected; collision → `ErrConnectionIDCollision` | `TestConnectionID_*` | Yes |
| P-256 G_X / G_Y are 32 bytes (x-coordinate) | covered by trace test for suite 2 | Yes |
| OSCORE SenderID = peer's connection ID; RecipientID = own | `TestOSCORE_IDMapping` + trace | Yes |
| Any processing error → state `Failed`; next call → `ErrStateViolation`; secrets zeroed (checked via test hook) | `TestStateMachine_FailTerminal` | Yes |
| `Close` zeroizes ephemeral key and PRKs | `TestClose_Zeroizes` (internal test) | Yes |
| ID_CRED compact kid, x5t, kccs parse; resolver receives parsed `IDCred` and its error is wrapped by `ErrCredentialRejected` | `TestIDCred_*` | Yes |
| No `PeerPublic` fallback as CWT issuer key (`CWTIssuerKey` nil with a CWT credential → error; fields unchanged) | `TestCredential_NoIssuerFallback` | Yes |
| EC2 credential point not on curve → error | `TestCredential_OffCurve` | Yes |
| Unknown critical EAD → `ErrCriticalEAD`; non-critical ignored and surfaced via `PeerEAD()` | `TestEAD_*` | Yes |
| KMS-style `crypto.Signer` (wrapper type) in `PrivateKey` works for suites 0 and 2 | `TestPrivateKey_GenericSigner` | Yes |
| A v0.2.2-style config (`PrivateKey` + `PeerPublic`, no `Peers`) completes an RFC 9528 handshake with the peer pinned | `TestConfigV022Shape` | Yes |
| `FuzzProcessMessage1/2/3` 60 s, no panic | fuzz | Yes |
| `golang.org/x/crypto` used only for ChaCha20-Poly1305 | `go list -deps ./edhoc` shows only `x/crypto/chacha20poly1305` (+ its internals) | Yes |
| Interop smoke test against an external implementation (lakers or uoscore-uedhoc) | manual, documented in PR | No |
| Default sessions never speak the pre-RFC protocol: a v0.3 initiator against a v0.2.2 responder fixture fails cleanly with an error, never a partial OSCORE context | `TestCompatDefaultRejectsLegacyPeer` | Yes |
| Two v0.3 peers with `WithLegacyPreRFCProtocol` reproduce the captured v0.2.2 transcripts byte-for-byte (fixed ephemeral keys), and interoperate with a v0.2.2 peer | `TestCompatLegacyPreRFCTranscript` vs `testdata/legacy-v0.2.2/edhoc/` | Yes |
| `WithLegacyPreRFCProtocol` carries `// Deprecated:` with removal floor v0.5.0 and appears in no bundle | staticcheck SA1019 fixture + API review | Yes |
| No exported identifier present in v0.2.2 is removed, renamed, or retyped, and no method is added to an exported interface (034 API stability) | `apidiff` against `v0.2.2` for this module, run in `make check` | Yes |
| Existing identifiers called with no new options reproduce the v0.2.2 golden vectors, except the contract-defect fixes listed under Compatibility selection | `testdata/legacy-v0.2.2/` golden tests | Yes |

---

## Phases

| Phase | Scope | Status | Closes when |
|---|---|---|---|
| 0 | Mark module experimental; mark 004 Superseded (done 2026-11-20); vendor RFC 9528 / 9529; capture v0.2.2 handshake transcripts as legacy fixtures | Pending | doc + fixtures merged |
| A | Key schedule, transcripts, message encodings, suite selection, C_ID rules, MAC / Sig / Enc structures, method 0, suites 0 and 2 | Pending | Method-0 RFC 9529 traces pass |
| B | Credentials: `IDCred`, `CredentialResolver`, CCS / CWT / X.509-by-reference, EAD items, error messages, fail-terminal state machine, zeroize, generic `crypto.Signer` | Pending | `TestIDCred_*`, `TestStateMachine_*`, `TestEAD_*` pass |
| C | Exporter, PRK_out, KeyUpdate, OSCORE context; RFC 9668 CoAP prefix helpers | Pending | OSCORE trace values + `TestOSCORE_IDMapping` pass |
| D | Methods 1–3 (static DH authentication) | Pending | Remaining RFC 9529 traces pass |

Phases A and C together restore the original 004 promise. Phase 0 ships
first, so that nobody adopts the module in its current state.

---

## Test surface

| Test | Covers | Lives at |
|---|---|---|
| `TestRFC9529_Trace*` | golden intermediate values | `edhoc/rfc9529_test.go` + `edhoc/testdata/rfc9529/*.json` (transcribed from the RFC) |
| `TestStateMachine_*` | ordering, terminal failure | `edhoc/state_test.go` |
| `TestIDCred_*`, `TestCredential_*` | credential parsing / resolution | `edhoc/credential_test.go` |
| `FuzzProcessMessage{1,2,3}` | adversarial messages | `edhoc/fuzz_test.go` (new) |

The existing `edhoc_test.go` and `phase_c_test.go` round-trip tests are
deleted. They pass only because both sides share the same
non-conformant derivation.

---

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Transcription errors in RFC 9529 trace data | med | med | Transcribe from vendored text by script where possible; cross-check against a second implementation's test vectors |
| Callers relying on the swapped `ExportOSCORE` IDs or v0.2 key schedule break on upgrade | high | low | Contract-defect fix with `WithLegacyPreRFCProtocol()`; the module isn't interoperable today; Phase 0 warns early; migration guide entry |
| AES-CCM in `edhoc/internal/aesccm` has its own defects | low | high | The RFC 9529 traces exercise it; add NIST CCM vectors if missing |
| Draft churn in LAKE (PSK method, app profiles) | med | low | Design keeps `Method` open-ended; nothing in this proposal depends on drafts |

---

## Alternatives considered

**Patch the existing code in place.** Rejected. Nearly every derivation
and message encoding changes, and the current round-trip tests give no
safety net because both sides are wrong the same way. A rewrite that
follows the RFC's structure and is gated on traces is cheaper to review.
The rewrite is internal: the exported API is preserved (proposal 034).

**Redesign the config (`AuthKey`, `ConnectionID` type, resolver-only
peers, ctx on every method).** Cleaner, but removes/retypes v0.2.2
fields and changes method signatures. Rejected under 034; new fields
and `…Context` methods are added beside the existing ones.

**Wrap an existing implementation (lakers via cgo / WASM).** Rejected
for the same reasons 004 rejected external libraries: no cgo, no
non-stdlib dependencies, and the CBOR stack should be this repository's.

**Drop EDHOC from the repository.** Considered. Kept, because OSCORE
and ACE consumers are a stated target and the module is small. If
Phase A doesn't land in a reasonable window, mark the module
**Withdrawn** and remove it rather than ship non-conformant crypto.

---

## Open questions

- Should `OSCORE()` live in `edhoc` or in a future `oscore` module?
  The proposal keeps it in `edhoc` because the inputs are
  EDHOC-specific, and RFC 9528 Appendix A.1 defines it there.
- Should a responder support concurrent sessions keyed by C_R through
  a `ResponderPool` helper, or leave that to the application? The
  leaning is to leave it to the application, documented with an example.

### Verify during implementation

- Exact `info_label` numbering and `mac_length` rules: quote RFC 9528
  §4.1.2 and §5.3.2 from the vendored text. The table above is from the
  reviewer's reading.
- Exact ERR_CODE values and the `SUITES_R` encoding (§6.3).
- The RFC 9668 prefix encoding (`true` for message_1, C_R otherwise) and
  whether message_2 also carries a prefix.

### Watch items (LAKE WG, as of 2026-11-20)

| Draft | State | Relevance |
|---|---|---|
| `draft-ietf-lake-edhoc-psk-11` | WG consensus, waiting for write-up | New PSK method; `Method` enum must accept it |
| `draft-ietf-lake-app-profiles-07` | Submitted to IESG | Profile signalling; affects `CredentialResolver` docs |
| `draft-ietf-lake-edhoc-impl-cons-08` | Submitted to IESG | Zeroization, state handling, side-channel guidance; review against Phase B |
| `draft-ietf-lake-edhoc-grease-04` | Submitted to IESG | Ignore unknown non-critical EAD and suites; test with GREASE values |
| `draft-ietf-lake-authz-08` | WG Last Call | EAD-based authorization (ELA); consumer of `EADItem` |
| `draft-ietf-lake-ra-07` | WG document | Remote attestation via EAD; pairs with proposal 032 |
| `draft-ietf-lake-pqsuites-02` | WG document | Post-quantum suites; suite parameter table must be extensible |
| `draft-ietf-lake-authkem-edhoc-01` | WG document | KEM-based authentication method |
| `draft-ietf-lake-private-use-ranges-00` | WG document | Private-use ranges for suites / EAD labels |
| `draft-ietf-ace-edhoc-oscore-profile-12` | ACE WG | ACE consumer of `CredentialResolver` + `OSCORE()` |

---

## Cross-references

- RFCs: RFC 9528 §3, §4, §5, §6 and Appendix A. RFC 9529 (traces).
  RFC 9668 (EDHOC + OSCORE over CoAP). RFC 8613 (OSCORE). RFC 9360
  (x5chain / x5t). RFC 8392 / RFC 9781 (CWT / CCS).
- Sibling proposals: 004 (superseded core), 022, 028, 031, 032.

---

## Changelog

| Date | Change | Author |
|---|---|---|
| 2026-11-20 | Initial draft from 2026-11-20 codebase review | corecbor maintainers |
| 2026-11-20 | Compatibility selection per 034 | corecbor maintainers |
| 2026-11-20 | API stability (signature + semantics) per revised 034 | corecbor maintainers |
| 2026-11-21 | In-Progress: protocol core per RFC 9528, gated on RFC 9529 traces (both pass); implementation notes | corecbor maintainers |
| 2026-11-21 | Follow-ups: cose key API, CoAP/RFC 9668 helpers, X.509 resolver, acceptance tests and sentinels; all gating criteria met except x/crypto removal (maintainer decision) | corecbor maintainers |
| 2026-11-22 | Criterion amended: x/crypto only for ChaCha20-Poly1305 (maintainer decision). Status: Closed; edhoc no longer experimental | corecbor maintainers |
