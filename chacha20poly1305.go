// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.
//
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package chacha20poly1305 implements the AEAD_CHACHA20_POLY1305 algorithm,
// which combines ChaCha20, a secure stream cipher, with Poly1305, a secure MAC
// function.
//
//     ChaCha20 is run with the given key and nonce and with the two counter
//     words set to zero. The first 32 bytes of the 64 byte output are saved to
//     become the one-time key for Poly1305. The remainder of the output is
//     discarded. The first counter input word is set to one and the plaintext
//     is encrypted by XORing it with the output of invocations of the ChaCha20
//     function as needed, incrementing the first counter word after each block
//     and overflowing into the second.  (In the case of the TLS, limits on the
//     plaintext size mean that the first counter word will never overflow in
//     practice.)
//
//     The Poly1305 key is used to calculate a tag for the following input: the
//     concatenation of the number of bytes of additional data, the additional
//     data itself, the number of bytes of ciphertext and the ciphertext
//     itself. Numbers are represented as 8-byte, little-endian values.  The
//     resulting tag is appended to the ciphertext, resulting in the output of
//     the AEAD operation.
//
// (http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04)
//
// The AEAD (Athenticated Encryption with Associated Data) construction provides
// a unified API for sealing messages in a way which provides both
// confidentiality *and* integrity. Unlike unauthenticated modes like CBC, AEAD
// algorithms are resistant to chosen ciphertext attacks, such as padding oracle
// attacks, etc., and add only 16 bytes of overhead.
//
// AEAD_CHACHA20_POLY1305 has a significant speed advantage over other AEAD
// algorithms like AES-GCM, as well as being extremely resistant to timing
// attacks.
package chacha20poly1305

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/tmthrgd/chacha20"
	"golang.org/x/crypto/poly1305"
)

const (
	// KeySize is the required size of ChaCha20 keys.
	KeySize = chacha20.KeySize
)

var (
	// ErrAuthFailed is returned when the message authentication is invalid due
	// to tampering.
	ErrAuthFailed = errors.New("message authentication failed")

	// ErrInvalidKey is returned when the provided key is the wrong size.
	ErrInvalidKey = errors.New("invalid key size")

	// ErrInvalidNonce is returned when the provided nonce is the wrong size.
	ErrInvalidNonce = errors.New("invalid nonce size")
)

// New creates a new AEAD instance using the given key. The key must be exactly
// 256 bits long.
func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	k := new(chacha20Key)
	for i, v := range key {
		k[i] = v
	}

	return k, nil
}

type chacha20Key [chacha20.KeySize]byte // A 256-bit ChaCha20 key.

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

	c, err := chacha20.New(k[:], nonce)
	if err != nil {
		panic(err) // basically impossible
	}

	ret, out := sliceForAppend(dst, len(plaintext) + poly1305.TagSize)

	var pk [32]byte
	c.XORKeyStream(pk[:], pk[:])
	var dummy [32]byte
	c.XORKeyStream(dummy[:], dummy[:])

	c.XORKeyStream(out, plaintext)

	auth(&pk, out[len(plaintext):], out[:len(plaintext)], data)
	return ret
}

func (k *chacha20Key) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != k.NonceSize() {
		return nil, ErrInvalidNonce
	}

	tag := ciphertext[len(ciphertext)-poly1305.TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-poly1305.TagSize]

	c, err := chacha20.New(k[:], nonce)
	if err != nil {
		return nil, err
	}

	var pk [32]byte
	c.XORKeyStream(pk[:], pk[:])
	var dummy [32]byte
	c.XORKeyStream(dummy[:], dummy[:])

	var expectedTag [poly1305.TagSize]byte
	auth(&pk, expectedTag[:], ciphertext, data)

	if subtle.ConstantTimeCompare(expectedTag[:], tag) != 1 {
		return nil, ErrAuthFailed
	}

	ret, out := sliceForAppend(dst, len(ciphertext))
	c.XORKeyStream(out, ciphertext)
	return ret, nil
}

func auth(key *[32]byte, out, ciphertext, data []byte) {
	m := make([]byte, len(data)+8+len(ciphertext)+8)

	copy(m[:], data)
	binary.LittleEndian.PutUint64(m[len(data):], uint64(len(data)))

	copy(m[len(data)+8:], ciphertext)
	binary.LittleEndian.PutUint64(m[len(data)+8+len(ciphertext):], uint64(len(ciphertext)))

	var tag [poly1305.TagSize]byte
	poly1305.Sum(&tag, m, key)

	copy(out, tag[:])
	return
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
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
