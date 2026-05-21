package edhoc

import (
	"crypto/ecdh"
)

type CipherSuite int64

const (
	Suite0 CipherSuite = 0
	Suite2 CipherSuite = 2
)

// suiteParams holds the cipher suite parameters.
type suiteParams struct {
	AEADKeySize  int
	AEADTagSize  int
	AEADNonceLen int
	HashSize     int
	DHCurve      ecdh.Curve
}

// Suite 0 and Suite 2 share AEAD (AES-CCM-16-64-128) and hash (SHA-256).
// They differ in DH curve and signature algorithm.
const (
	suite0AEADKeySize  = 16
	suite0AEADTagSize  = 8
	suite0AEADNonceLen = 13
	suite0HashSize     = 32
)

func getSuiteParams(suite CipherSuite) suiteParams {
	switch suite {
	case Suite2:
		return suiteParams{
			AEADKeySize:  16,
			AEADTagSize:  8,
			AEADNonceLen: 13,
			HashSize:     32,
			DHCurve:      ecdh.P256(),
		}
	default: // Suite0
		return suiteParams{
			AEADKeySize:  16,
			AEADTagSize:  8,
			AEADNonceLen: 13,
			HashSize:     32,
			DHCurve:      ecdh.X25519(),
		}
	}
}

func isSuiteSupported(suite CipherSuite) bool {
	return suite == Suite0 || suite == Suite2
}
