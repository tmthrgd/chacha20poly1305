// Package chacha20poly1305 implements the AEAD_CHACHA20_POLY1305 algorithm
// specified in draft-agl-tls-chacha20poly1305-03:
//
//     ChaCha20 is run with the given key and nonce and with the two counter
//     words set to zero.  The first 32 bytes of the 64 byte output are
//     saved to become the one-time key for Poly1305.  The remainder of the
//     output is discarded.  The first counter input word is set to one and
//     the plaintext is encrypted by XORing it with the output of
//     invocations of the ChaCha20 function as needed, incrementing the
//     first counter word after each block and overflowing into the second.
//     (In the case of the TLS, limits on the plaintext size mean that the
//     first counter word will never overflow in practice.)
//
//     The Poly1305 key is used to calculate a tag for the following input:
//     the concatenation of the number of bytes of additional data, the
//     additional data itself, the number of bytes of ciphertext and the
//     ciphertext itself.  Numbers are represented as 8-byte, little-endian
//     values.  The resulting tag is appended to the ciphertext, resulting
//     in the output of the AEAD operation.
//
// http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03
package chacha20poly1305

import (
	"code.google.com/p/go.crypto/poly1305"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"github.com/codahale/chacha20"
)

type chacha20Key [chacha20.KeySize]byte // A 256-bit ChaCha20 key.

var (
	// ErrAuthFailed is returned when the message authentication is invalid due
	// to tampering.
	ErrAuthFailed = errors.New("chacha20poly1305: message authentication failed")

	// ErrInvalidKey is returned when the provided key is the wrong size.
	ErrInvalidKey = errors.New("chacha20poly1305: invalid key size")

	// ErrInvalidNonce is returned when the provided nonce is the wrong size.
	ErrInvalidNonce = errors.New("chacha20poly1305: invalid nonce size")

	// KeySize is the required size of ChaCha20 keys.
	KeySize = chacha20.KeySize
)

// NewChaCha20Poly1305 creates a new AEAD instance using the given key. The key
// must be exactly 256 bits long.
func NewChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	k := new(chacha20Key)
	for i, v := range key {
		k[i] = v
	}

	return k, nil
}

func (*chacha20Key) NonceSize() int {
	return chacha20.NonceSize
}

func (*chacha20Key) Overhead() int {
	return poly1305.TagSize
}

func (k *chacha20Key) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != k.NonceSize() {
		panic(ErrInvalidNonce)
	}

	c, pk := k.initialize(nonce)

	ciphertext := make([]byte, len(plaintext))
	c.XORKeyStream(ciphertext, plaintext)

	tag := tag(pk, ciphertext, data)

	return append(dst, append(ciphertext, tag...)...)
}

func (k *chacha20Key) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != k.NonceSize() {
		return nil, ErrInvalidNonce
	}

	digest := ciphertext[len(ciphertext)-k.Overhead():]
	ciphertext = ciphertext[0 : len(ciphertext)-k.Overhead()]

	c, pk := k.initialize(nonce)

	tag := tag(pk, ciphertext, data)

	if subtle.ConstantTimeCompare(tag, digest) != 1 {
		return nil, ErrAuthFailed
	}

	plaintext := make([]byte, len(ciphertext))
	c.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}

// Converts the given key and nonce into 64 bytes of ChaCha20 key stream, the
// first 32 of which are used as the Poly1305 key.
func (k *chacha20Key) initialize(nonce []byte) (cipher.Stream, [32]byte) {
	c, err := chacha20.NewCipher(k[0:], nonce)
	if err != nil {
		panic(err) // basically impossible
	}

	subkey := make([]byte, 64)
	c.XORKeyStream(subkey, subkey)

	var key [32]byte
	for i := 0; i < 32; i++ {
		key[i] = subkey[i]
	}

	return c, key
}

func tag(key [32]byte, ciphertext, data []byte) []byte {
	dataLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataLen, uint64(len(data)))

	ciphertextLen := make([]byte, 8)
	binary.LittleEndian.PutUint64(ciphertextLen, uint64(len(ciphertext)))

	message := append(append(append(data, dataLen...), ciphertext...), ciphertextLen...)

	var out [poly1305.TagSize]byte
	poly1305.Sum(&out, message, &key)

	return out[0:]
}
