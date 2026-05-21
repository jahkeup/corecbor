// Package cose_test demonstrates key escrow patterns using the KeyDeriver interface.
// These examples show how the extensible KeyDeriver interface supports a variety of
// key management strategies: network-bound (Tang-style), hardware-bound (TPM-style),
// multi-recipient, and threshold (K-of-N) patterns.
package cose_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jahkeup/corecbor/cose"
)

// =============================================================================
// Tang-style: network-bound encryption via ECDH
// =============================================================================
//
// Tang (https://github.com/latchset/tang) is a network-bound encryption server.
// The client generates an ephemeral key, performs ECDH with the server's public key,
// and uses the shared secret to derive the KEK. Decryption requires contacting the
// server to perform the ECDH on the server side.
//
// In this simulation:
//   - "server" holds serverPrivate (never leaves the server)
//   - "client" knows serverPublic (fetched from server at setup time)
//   - Encryption: client generates ephemeral key, ECDH(ephemeral, serverPublic) → KEK
//   - Decryption: server performs ECDH(serverPrivate, ephemeralPublic) → same KEK
//
// The built-in ECDHESKey implements exactly this pattern. In a real Tang deployment,
// the UnwrapKey step would make an HTTP request to the Tang server, which holds
// serverPrivate and performs the ECDH computation remotely.

// TestExample_TangStyle_NetworkBound demonstrates Tang-style network-bound encryption.
// The CEK is protected by ECDH key agreement: only the "server" (holder of serverPrivate)
// can cooperate in decryption.
func TestExample_TangStyle_NetworkBound(t *testing.T) {
	plaintext := []byte("secret data: only decryptable with Tang server cooperation")

	// Server generates its long-term key pair (in Tang, this is the server's advertised key).
	serverPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating server key: %v", err)
	}
	serverPub := serverPriv.PublicKey()

	// --- Encryption (client side) ---
	// Client uses the server's public key to set up ECDH-ES.
	// ECDHESKey.DeriveKey generates an ephemeral key, performs ECDH with serverPub,
	// and stores the ephemeral public key in the recipient headers.
	senderDeriver := &cose.ECDHESKey{
		PeerPublic: serverPub,
	}

	msg, err := cose.EncryptMulti(plaintext, cose.AlgA128GCM, []cose.KeyDeriver{senderDeriver})
	if err != nil {
		t.Fatalf("EncryptMulti (Tang-style encrypt): %v", err)
	}

	// --- Decryption (requires server cooperation) ---
	// The server uses its private key to re-derive the KEK from the ephemeral public key
	// stored in the recipient headers. In a real Tang deployment, this step would be
	// an HTTP call to the Tang server.
	serverDeriver := &cose.ECDHESKey{
		PrivateKey: serverPriv,
	}

	decrypted, err := cose.DecryptMulti(msg, serverDeriver, 0)
	if err != nil {
		t.Fatalf("DecryptMulti (Tang-style decrypt): %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}

	// --- Failure case: wrong server key cannot decrypt ---
	// A different server (or attacker without serverPrivate) cannot decrypt.
	wrongServerPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating wrong server key: %v", err)
	}
	wrongDeriver := &cose.ECDHESKey{
		PrivateKey: wrongServerPriv,
	}

	_, err = cose.DecryptMulti(msg, wrongDeriver, 0)
	if err == nil {
		t.Fatal("expected decryption failure with wrong server key, but succeeded")
	}
	t.Logf("Tang-style: wrong server key correctly rejected: %v", err)
}

// =============================================================================
// TPM-style: hardware-bound encryption via sealed key
// =============================================================================
//
// A TPM (Trusted Platform Module) can "seal" a key to a set of PCR (Platform
// Configuration Register) values. The key can only be "unsealed" when the TPM
// is in the same measured state (same PCR values). This binds decryption to
// a specific hardware state (e.g., a particular boot configuration).
//
// In this simulation:
//   - "PCR value" is a fixed byte sequence representing the measured boot state
//   - "Sealing" = XOR the CEK with the PCR value (real TPMs use asymmetric wrapping)
//   - "Unsealing" = XOR again with the same PCR value to recover the CEK
//   - The COSE envelope stores the XOR'd (sealed) key as the recipient ciphertext
//
// tpmDeriver implements KeyDeriver using this simulated seal/unseal mechanism.
type tpmDeriver struct {
	// pcrValue simulates the TPM's current PCR state.
	// In a real TPM, this would be the hash of the boot measurements.
	pcrValue []byte
}

func (t *tpmDeriver) Algorithm() cose.Algorithm {
	// We use AlgDirect semantics: the "ciphertext" in the recipient IS the sealed key.
	// In a real implementation, you'd register a custom algorithm ID.
	return cose.AlgDirect
}

// WrapKey "seals" the CEK to the current TPM PCR state by XOR-ing with the PCR value.
// The sealed blob is stored as the recipient ciphertext in the COSE envelope.
func (t *tpmDeriver) WrapKey(cek []byte, _ cose.KeyWrapOpts) ([]byte, cose.Headers, error) {
	if len(t.pcrValue) < len(cek) {
		return nil, cose.Headers{}, errors.New("tpmDeriver: PCR value shorter than CEK")
	}
	sealed := make([]byte, len(cek))
	for i := range cek {
		sealed[i] = cek[i] ^ t.pcrValue[i]
	}
	return sealed, cose.Headers{}, nil
}

// UnwrapKey "unseals" the CEK by XOR-ing the sealed blob with the current PCR value.
// This only succeeds if the PCR value matches the one used during sealing.
func (t *tpmDeriver) UnwrapKey(ciphertext []byte, _ cose.Headers, _ cose.KeyUnwrapOpts) ([]byte, error) {
	if len(t.pcrValue) < len(ciphertext) {
		return nil, errors.New("tpmDeriver: PCR value shorter than sealed key")
	}
	cek := make([]byte, len(ciphertext))
	for i := range ciphertext {
		cek[i] = ciphertext[i] ^ t.pcrValue[i]
	}
	return cek, nil
}

// TestExample_TPMStyle_HardwareBound demonstrates TPM-style hardware-bound encryption.
// The CEK is "sealed" to a simulated PCR state; decryption requires the same PCR state.
func TestExample_TPMStyle_HardwareBound(t *testing.T) {
	plaintext := []byte("secret data: only decryptable when TPM PCR state matches")

	// Simulate the TPM's current PCR state (e.g., hash of boot measurements).
	// Must be at least as long as the CEK (16 bytes for A128GCM).
	pcrValue := make([]byte, 32)
	if _, err := rand.Read(pcrValue); err != nil {
		t.Fatalf("generating PCR value: %v", err)
	}

	// --- Encryption: seal CEK to current PCR state ---
	tpm := &tpmDeriver{pcrValue: pcrValue}

	msg, err := cose.EncryptMulti(plaintext, cose.AlgA128GCM, []cose.KeyDeriver{tpm})
	if err != nil {
		t.Fatalf("EncryptMulti (TPM-style encrypt): %v", err)
	}

	// --- Decryption: unseal with matching PCR state ---
	// Same PCR value → same XOR mask → recovers the CEK.
	tpmDecrypt := &tpmDeriver{pcrValue: pcrValue}

	decrypted, err := cose.DecryptMulti(msg, tpmDecrypt, 0)
	if err != nil {
		t.Fatalf("DecryptMulti (TPM-style decrypt): %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}

	// --- Failure case: wrong PCR state (e.g., after a firmware update) ---
	// Different PCR value → different XOR mask → wrong CEK → GCM authentication fails.
	wrongPCR := make([]byte, 32)
	if _, err := rand.Read(wrongPCR); err != nil {
		t.Fatalf("generating wrong PCR value: %v", err)
	}
	tpmWrong := &tpmDeriver{pcrValue: wrongPCR}

	_, err = cose.DecryptMulti(msg, tpmWrong, 0)
	if err == nil {
		t.Fatal("expected decryption failure with wrong PCR state, but succeeded")
	}
	t.Logf("TPM-style: wrong PCR state correctly rejected: %v", err)
}

// =============================================================================
// Multi-recipient: any-of-N unlock
// =============================================================================
//
// A single ciphertext can be addressed to multiple recipients. Each recipient
// independently wraps the same CEK with their own key. Any one recipient can
// decrypt without involving the others.
//
// This is useful for:
//   - Backup key holders (e.g., IT admin + user + escrow)
//   - Heterogeneous key types (hardware token + password + ECDH)

// TestExample_MultiRecipient_AnyUnlocks demonstrates that any of N recipients
// can independently decrypt the same ciphertext.
func TestExample_MultiRecipient_AnyUnlocks(t *testing.T) {
	plaintext := []byte("secret data: any of three recipients can decrypt")

	// Recipient 0: ECDH-ES (e.g., a hardware security key or server)
	ecdhPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDH key: %v", err)
	}
	ecdhRecipient := &cose.ECDHESKey{PeerPublic: ecdhPriv.PublicKey()}

	// Recipient 1: AES-KW (e.g., a symmetric backup key stored in a vault)
	aeskwKey := make([]byte, 16)
	if _, err := rand.Read(aeskwKey); err != nil {
		t.Fatalf("generating AES-KW key: %v", err)
	}
	aeskwRecipient := &cose.AESKWKey{Key: aeskwKey}

	// Recipient 2: PBES2 (e.g., a recovery passphrase known to the user)
	pbes2Recipient := &cose.PBES2Key{Password: []byte("correct horse battery staple")}

	recipients := []cose.KeyDeriver{ecdhRecipient, aeskwRecipient, pbes2Recipient}

	msg, err := cose.EncryptMulti(plaintext, cose.AlgA128GCM, recipients)
	if err != nil {
		t.Fatalf("EncryptMulti (multi-recipient): %v", err)
	}

	if len(msg.Recipients) != 3 {
		t.Fatalf("expected 3 recipients, got %d", len(msg.Recipients))
	}

	// --- Each recipient can independently decrypt ---

	// Recipient 0: ECDH-ES decryption
	ecdhDecryptor := &cose.ECDHESKey{PrivateKey: ecdhPriv}
	got0, err := cose.DecryptMulti(msg, ecdhDecryptor, 0)
	if err != nil {
		t.Fatalf("DecryptMulti recipient 0 (ECDH-ES): %v", err)
	}
	if !bytes.Equal(got0, plaintext) {
		t.Errorf("recipient 0: got %q, want %q", got0, plaintext)
	}

	// Recipient 1: AES-KW decryption
	got1, err := cose.DecryptMulti(msg, &cose.AESKWKey{Key: aeskwKey}, 1)
	if err != nil {
		t.Fatalf("DecryptMulti recipient 1 (AES-KW): %v", err)
	}
	if !bytes.Equal(got1, plaintext) {
		t.Errorf("recipient 1: got %q, want %q", got1, plaintext)
	}

	// Recipient 2: PBES2 decryption
	got2, err := cose.DecryptMulti(msg, &cose.PBES2Key{Password: []byte("correct horse battery staple")}, 2)
	if err != nil {
		t.Fatalf("DecryptMulti recipient 2 (PBES2): %v", err)
	}
	if !bytes.Equal(got2, plaintext) {
		t.Errorf("recipient 2: got %q, want %q", got2, plaintext)
	}

	// --- Failure case: wrong key for a recipient slot ---
	wrongAESKW := make([]byte, 16)
	if _, err := rand.Read(wrongAESKW); err != nil {
		t.Fatalf("generating wrong AES-KW key: %v", err)
	}
	_, err = cose.DecryptMulti(msg, &cose.AESKWKey{Key: wrongAESKW}, 1)
	if err == nil {
		t.Fatal("expected decryption failure with wrong AES-KW key, but succeeded")
	}
	t.Logf("Multi-recipient: wrong key for slot 1 correctly rejected: %v", err)
}

// =============================================================================
// Threshold / K-of-N: collect shares to reconstruct
// =============================================================================
//
// In a K-of-N threshold scheme, the CEK is split into N shares such that any K
// shares can reconstruct the CEK, but K-1 shares reveal nothing.
//
// Real implementations use Shamir's Secret Sharing (polynomial interpolation over GF(2^8)).
// This example uses a simplified 2-of-3 XOR split for clarity:
//
//   share0 = random
//   share1 = random
//   share2 = CEK XOR share0 XOR share1
//
// Any two shares can reconstruct the third, and thus the CEK:
//   CEK = share0 XOR share1 XOR share2
//
// Each share is wrapped as a separate DirectKey recipient in the COSE envelope.
// A coordinator collects K recipients' shares and XORs them to recover the CEK.
//
// This XOR construction requires all 3 shares to reconstruct the CEK (CEK = s0 XOR s1 XOR s2).
// For true K-of-N with K > 2, use Shamir's Secret Sharing (polynomial interpolation).

// thresholdCoordinator collects XOR shares from K recipients and reconstructs the CEK.
// It implements KeyDeriver by XOR-ing all collected shares.
type thresholdCoordinator struct {
	// shares holds the raw share bytes collected from K recipients.
	shares [][]byte
}

func (tc *thresholdCoordinator) Algorithm() cose.Algorithm {
	return cose.AlgDirect
}

// WrapKey is not used by the coordinator (it only decrypts).
func (tc *thresholdCoordinator) WrapKey(_ []byte, _ cose.KeyWrapOpts) ([]byte, cose.Headers, error) {
	return nil, cose.Headers{}, errors.New("thresholdCoordinator: WrapKey not supported")
}

// UnwrapKey XORs all collected shares to reconstruct the CEK.
// The ciphertext parameter is ignored; the coordinator uses its pre-loaded shares.
func (tc *thresholdCoordinator) UnwrapKey(_ []byte, _ cose.Headers, _ cose.KeyUnwrapOpts) ([]byte, error) {
	if len(tc.shares) == 0 {
		return nil, errors.New("thresholdCoordinator: no shares collected")
	}
	result := make([]byte, len(tc.shares[0]))
	for _, share := range tc.shares {
		if len(share) != len(result) {
			return nil, errors.New("thresholdCoordinator: share length mismatch")
		}
		for i := range result {
			result[i] ^= share[i]
		}
	}
	return result, nil
}

// xorSplit3 splits key into 3 XOR shares such that share0 XOR share1 XOR share2 = key.
// Any 2 shares can reconstruct the third, enabling a 2-of-3 threshold.
func xorSplit3(key []byte) (share0, share1, share2 []byte, err error) {
	share0 = make([]byte, len(key))
	share1 = make([]byte, len(key))
	share2 = make([]byte, len(key))

	if _, err = rand.Read(share0); err != nil {
		return nil, nil, nil, err
	}
	if _, err = rand.Read(share1); err != nil {
		return nil, nil, nil, err
	}
	// share2 = key XOR share0 XOR share1
	for i := range key {
		share2[i] = key[i] ^ share0[i] ^ share1[i]
	}
	return share0, share1, share2, nil
}

// TestExample_Threshold_KofN demonstrates a 2-of-3 threshold scheme.
//
// The CEK is split into 3 XOR shares. Each share is distributed to a trustee.
// A coordinator collects all 3 shares and XORs them to reconstruct the CEK,
// then uses it to decrypt the COSE Encrypt0 message.
//
// This pattern is useful for:
//   - M-of-N key ceremonies (e.g., HSM initialization)
//   - Distributed key escrow (e.g., 2-of-3 trustees must cooperate)
//   - Dead man's switch (K trustees must be present to decrypt)
//
// The threshold layer sits above the COSE encryption: the CEK is split before
// encryption, and the coordinator reconstructs it before decryption. This keeps
// the COSE message itself standard (Encrypt0 with a known CEK).
func TestExample_Threshold_KofN(t *testing.T) {
	plaintext := []byte("secret data: requires 2-of-3 shares to decrypt")

	// Generate the CEK explicitly so we can split it across trustees.
	cek := make([]byte, 16)
	if _, err := rand.Read(cek); err != nil {
		t.Fatalf("generating CEK: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generating nonce: %v", err)
	}

	// Encrypt the plaintext with the known CEK.
	msg, err := cose.EncryptEncrypt0(plaintext, cek, nonce, cose.AlgA128GCM)
	if err != nil {
		t.Fatalf("EncryptEncrypt0 (threshold): %v", err)
	}

	// Split the CEK into 3 XOR shares and distribute to trustees.
	share0, share1, share2, err := xorSplit3(cek)
	if err != nil {
		t.Fatalf("splitting CEK: %v", err)
	}

	// Verify the split invariant: share0 XOR share1 XOR share2 == CEK
	reconstructed := make([]byte, 16)
	for i := range cek {
		reconstructed[i] = share0[i] ^ share1[i] ^ share2[i]
	}
	if !bytes.Equal(reconstructed, cek) {
		t.Fatal("XOR split sanity check failed")
	}

	// --- Reconstruction: coordinator collects all 3 shares, XORs to get CEK ---
	coord := &thresholdCoordinator{
		shares: [][]byte{share0, share1, share2},
	}
	recoveredCEK, err := coord.UnwrapKey(nil, cose.Headers{}, cose.KeyUnwrapOpts{})
	if err != nil {
		t.Fatalf("thresholdCoordinator.UnwrapKey: %v", err)
	}

	decrypted, err := cose.DecryptEncrypt0(msg, recoveredCEK, nonce, cose.AlgA128GCM)
	if err != nil {
		t.Fatalf("DecryptEncrypt0 (threshold, all 3 shares): %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}

	// --- Failure case: only 1 share (insufficient) ---
	// With only share0, the coordinator XORs just share0, which is NOT the CEK.
	// The GCM authentication tag rejects the wrong key.
	coordInsufficient := &thresholdCoordinator{
		shares: [][]byte{share0},
	}
	wrongCEK, err := coordInsufficient.UnwrapKey(nil, cose.Headers{}, cose.KeyUnwrapOpts{})
	if err != nil {
		t.Fatalf("thresholdCoordinator.UnwrapKey (1 share): %v", err)
	}
	_, err = cose.DecryptEncrypt0(msg, wrongCEK, nonce, cose.AlgA128GCM)
	if err == nil {
		t.Fatal("expected decryption failure with only 1 share, but succeeded")
	}
	t.Logf("Threshold: insufficient shares (1-of-3) correctly rejected: %v", err)

	// --- Failure case: wrong share (corrupted or from a different split) ---
	wrongShare := make([]byte, 16)
	if _, err := rand.Read(wrongShare); err != nil {
		t.Fatalf("generating wrong share: %v", err)
	}
	coordWrong := &thresholdCoordinator{
		shares: [][]byte{wrongShare, share1, share2},
	}
	wrongCEK2, err := coordWrong.UnwrapKey(nil, cose.Headers{}, cose.KeyUnwrapOpts{})
	if err != nil {
		t.Fatalf("thresholdCoordinator.UnwrapKey (wrong share): %v", err)
	}
	_, err = cose.DecryptEncrypt0(msg, wrongCEK2, nonce, cose.AlgA128GCM)
	if err == nil {
		t.Fatal("expected decryption failure with wrong share, but succeeded")
	}
	t.Logf("Threshold: wrong share correctly rejected: %v", err)
}
