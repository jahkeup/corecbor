package edhoc

import (
	"crypto/ecdh"
	"crypto/sha256"
	"io"

	"github.com/jahkeup/corecbor/cbor"

	"golang.org/x/crypto/hkdf"
)

func computeSharedSecret(privKey *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	return privKey.ECDH(peerPub)
}

// TH_2 = SHA-256(H(message_1) || data_2)
// where data_2 = G_Y || C_R (as CBOR sequence)
func computeTH2(message1Raw, gY, cR []byte) []byte {
	h := sha256.New()
	h.Write(message1Raw)
	// Encode G_Y and C_R as CBOR sequence appended to transcript
	gyEnc, _ := cborEncodeValue(nil, cbor.Bytes(gY))
	h.Write(gyEnc)
	crEnc, _ := encodeConnectionID(nil, cR)
	h.Write(crEnc)
	return h.Sum(nil)
}

// TH_3 = SHA-256(TH_2 || CIPHERTEXT_2)
func computeTH3(th2, ciphertext2 []byte) []byte {
	h := sha256.New()
	thEnc, _ := cborEncodeValue(nil, cbor.Bytes(th2))
	h.Write(thEnc)
	ctEnc, _ := cborEncodeValue(nil, cbor.Bytes(ciphertext2))
	h.Write(ctEnc)
	return h.Sum(nil)
}

// TH_4 = SHA-256(TH_3 || CIPHERTEXT_3)
func computeTH4(th3, ciphertext3 []byte) []byte {
	h := sha256.New()
	thEnc, _ := cborEncodeValue(nil, cbor.Bytes(th3))
	h.Write(thEnc)
	ctEnc, _ := cborEncodeValue(nil, cbor.Bytes(ciphertext3))
	h.Write(ctEnc)
	return h.Sum(nil)
}

// PRK_2e = HKDF-Extract(salt="", IKM=ECDH shared secret)
func extractPRK2e(sharedSecret []byte) []byte {
	prk := hkdf.Extract(sha256.New, sharedSecret, nil)
	return prk
}

// EDHOC-KDF: info = CBOR array [transcript_hash, label, length]
// output = HKDF-Expand(PRK, info, length)
func edhocKDF(prk, transcriptHash []byte, label string, length int) ([]byte, error) {
	info, err := encodeCBORArray(
		cbor.Bytes(transcriptHash),
		cbor.Text(label),
		cbor.Uint(length),
	)
	if err != nil {
		return nil, err
	}
	r := hkdf.Expand(sha256.New, prk, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}
