package edhoc

type CipherSuite int64

const Suite0 CipherSuite = 0

const (
	suite0AEADKeySize  = 16
	suite0AEADTagSize  = 8
	suite0AEADNonceLen = 13
	suite0HashSize     = 32
)
