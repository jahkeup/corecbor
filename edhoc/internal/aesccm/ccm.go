// Package aesccm implements AES-CCM (Counter with CBC-MAC) as specified in
// RFC 3610, with parameters suitable for EDHOC Suite 0: 16-byte key,
// 13-byte nonce, 8-byte authentication tag.
package aesccm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
)

var (
	ErrInvalidTagSize   = errors.New("aesccm: tag size must be 4, 6, 8, 10, 12, 14, or 16")
	ErrInvalidNonceSize = errors.New("aesccm: nonce size must be 7-13")
	ErrOpen             = errors.New("aesccm: message authentication failed")
	ErrPlaintextTooLong = errors.New("aesccm: plaintext too long for nonce size")
)

type ccm struct {
	block    cipher.Block
	tagSize  int
	nonceLen int
}

// New creates a new AES-CCM AEAD with the given key, tag size, and nonce length.
// For EDHOC Suite 0: tagSize=8, nonceLen=13.
func New(key []byte, tagSize, nonceLen int) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, ErrInvalidTagSize
	}
	if nonceLen < 7 || nonceLen > 13 {
		return nil, ErrInvalidNonceSize
	}
	return &ccm{block: block, tagSize: tagSize, nonceLen: nonceLen}, nil
}

func (c *ccm) NonceSize() int { return c.nonceLen }
func (c *ccm) Overhead() int  { return c.tagSize }

func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceLen {
		panic("aesccm: incorrect nonce length")
	}
	if uint64(len(plaintext)) > c.maxMessageLen() {
		panic("aesccm: plaintext too long")
	}

	tag := c.computeTag(nonce, plaintext, additionalData)
	ret, out := sliceForAppend(dst, len(plaintext)+c.tagSize)

	c.ctr(nonce, out[:len(plaintext)], plaintext)
	// Encrypt the tag with counter 0
	var tagBlock [16]byte
	c.ctrBlock(nonce, 0, tagBlock[:])
	for i := range c.tagSize {
		out[len(plaintext)+i] = tag[i] ^ tagBlock[i]
	}
	return ret
}

func (c *ccm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceLen {
		return nil, ErrOpen
	}
	if len(ciphertext) < c.tagSize {
		return nil, ErrOpen
	}

	msgLen := len(ciphertext) - c.tagSize
	if uint64(msgLen) > c.maxMessageLen() {
		return nil, ErrOpen
	}

	ret, plaintext := sliceForAppend(dst, msgLen)

	// Decrypt the tag
	var tagBlock [16]byte
	c.ctrBlock(nonce, 0, tagBlock[:])
	var decTag [16]byte
	for i := range c.tagSize {
		decTag[i] = ciphertext[msgLen+i] ^ tagBlock[i]
	}

	// Decrypt the message
	c.ctr(nonce, plaintext, ciphertext[:msgLen])

	// Compute expected tag
	expectedTag := c.computeTag(nonce, plaintext, additionalData)

	if subtle.ConstantTimeCompare(decTag[:c.tagSize], expectedTag[:c.tagSize]) != 1 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, ErrOpen
	}
	return ret, nil
}

// q = 15 - nonceLen (length field size in bytes)
func (c *ccm) q() int { return 15 - c.nonceLen }

func (c *ccm) maxMessageLen() uint64 {
	q := c.q()
	if q >= 8 {
		return math.MaxUint64
	}
	return (1 << (8 * q)) - 1
}

// computeTag computes the CBC-MAC tag per RFC 3610 Section 2.2.
func (c *ccm) computeTag(nonce, plaintext, aad []byte) [16]byte {
	var b [16]byte
	q := c.q()

	// Flags: bit 6 = has AAD, bits 5-3 = (tagSize-2)/2, bits 2-0 = q-1
	flags := byte(q - 1)
	flags |= byte((c.tagSize-2)/2) << 3
	if len(aad) > 0 {
		flags |= 1 << 6
	}
	b[0] = flags
	copy(b[1:1+c.nonceLen], nonce)
	// Encode message length in last q bytes (big-endian)
	msgLen := len(plaintext)
	for i := range q {
		b[15-i] = byte(msgLen >> (8 * i))
	}

	var mac [16]byte
	c.block.Encrypt(mac[:], b[:])

	// Encode AAD
	if len(aad) > 0 {
		c.cbcAAD(&mac, aad)
	}

	// Encode plaintext
	c.cbcPlaintext(&mac, plaintext)

	return mac
}

func (c *ccm) cbcAAD(mac *[16]byte, aad []byte) {
	var lenBuf [10]byte
	var lenSize int

	alen := len(aad)
	if alen < (1<<16 - 1<<8) {
		binary.BigEndian.PutUint16(lenBuf[:2], uint16(alen))
		lenSize = 2
	} else if alen < (1 << 32) {
		lenBuf[0] = 0xff
		lenBuf[1] = 0xfe
		binary.BigEndian.PutUint32(lenBuf[2:6], uint32(alen))
		lenSize = 6
	} else {
		lenBuf[0] = 0xff
		lenBuf[1] = 0xff
		binary.BigEndian.PutUint64(lenBuf[2:10], uint64(alen))
		lenSize = 10
	}

	// Process length prefix + AAD in 16-byte blocks via CBC-MAC
	var block [16]byte
	pos := 0
	// First block: length prefix + beginning of AAD
	copy(block[:], lenBuf[:lenSize])
	remaining := 16 - lenSize
	n := copy(block[lenSize:], aad)
	pos = n
	xorBlock(mac, &block)
	c.block.Encrypt(mac[:], mac[:])

	if remaining < len(aad) {
		// Process remaining AAD
		for pos < len(aad) {
			block = [16]byte{}
			n = copy(block[:], aad[pos:])
			pos += n
			xorBlock(mac, &block)
			c.block.Encrypt(mac[:], mac[:])
		}
	}
}

func (c *ccm) cbcPlaintext(mac *[16]byte, plaintext []byte) {
	var block [16]byte
	for i := 0; i < len(plaintext); i += 16 {
		block = [16]byte{}
		copy(block[:], plaintext[i:])
		xorBlock(mac, &block)
		c.block.Encrypt(mac[:], mac[:])
	}
}

// ctr encrypts/decrypts using CTR mode starting at counter 1.
func (c *ccm) ctr(nonce []byte, dst, src []byte) {
	var keystreamBlock [16]byte
	for i := 0; i < len(src); i += 16 {
		counter := uint32(i/16) + 1
		c.ctrBlock(nonce, counter, keystreamBlock[:])
		end := i + 16
		if end > len(src) {
			end = len(src)
		}
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ keystreamBlock[j-i]
		}
	}
}

// ctrBlock generates keystream block for a given counter value.
// Format: flags(1) || nonce(nonceLen) || counter(q bytes)
func (c *ccm) ctrBlock(nonce []byte, counter uint32, out []byte) {
	var a [16]byte
	q := c.q()
	a[0] = byte(q - 1) // flags for CTR: just q-1
	copy(a[1:1+c.nonceLen], nonce)
	for i := range q {
		a[15-i] = byte(counter >> (8 * i))
	}
	c.block.Encrypt(out[:16], a[:])
}

func xorBlock(dst *[16]byte, src *[16]byte) {
	for i := range 16 {
		dst[i] ^= src[i]
	}
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
