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
	"sync"

	"github.com/tmthrgd/chacha20"
	"github.com/tmthrgd/poly1305"
)

const (
	// KeySize is the required size of ChaCha20 keys.
	KeySize = chacha20.KeySize

	poly1305PadLen = 16
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
// 256 bits long. New behaves like NewDraft.
//
// In most cases either NewRFC or NewDraft should be used instead.
//
// This is maintained for compatibility reasons.
func New(key []byte) (cipher.AEAD, error) {
	return NewDraft(key)
}

// NewRFC creates a new AEAD instance using the given key. The key must be exactly
// 256 bits long. The returned cipher is an implementation of the RFC7539 AEAD
// construct.
func NewRFC(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	k := new(chacha20Key)
	copy(k.key[:], key)
	return k, nil
}

// NewDraft creates a new AEAD instance using the given key. The key must be
// exactly 256 bits long. The returned cipher is an implementation of the
// draft-agl-tls-chacha20poly1305-03 AEAD construct.
func NewDraft(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	k := &chacha20Key{draft: true}
	copy(k.key[:], key)
	return k, nil
}

type chacha20Key struct {
	key [chacha20.KeySize]byte

	draft bool // draft or RFC
}

func (k *chacha20Key) NonceSize() int {
	if k.draft {
		return chacha20.DraftNonceSize
	}

	return chacha20.RFCNonceSize
}

func (*chacha20Key) Overhead() int {
	return poly1305.TagSize
}

func (k *chacha20Key) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != k.NonceSize() {
		panic(ErrInvalidNonce)
	}

	c, err := chacha20.New(k.key[:], nonce)
	if err != nil {
		panic(err) // basically impossible
	}

	ret, out := sliceForAppend(dst, len(plaintext)+poly1305.TagSize)

	var pk [64]byte
	c.XORKeyStream(pk[:], pk[:])

	c.XORKeyStream(out, plaintext)

	k.auth(pk[:poly1305.KeySize], out[len(plaintext):], out[:len(plaintext)], data)
	return ret
}

func (k *chacha20Key) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != k.NonceSize() {
		return nil, ErrInvalidNonce
	}

	if len(ciphertext) < poly1305.TagSize {
		return nil, ErrAuthFailed
	}

	tag := ciphertext[len(ciphertext)-poly1305.TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-poly1305.TagSize]

	c, err := chacha20.New(k.key[:], nonce)
	if err != nil {
		return nil, err
	}

	var pk [64]byte
	c.XORKeyStream(pk[:], pk[:])

	var expectedTag [poly1305.TagSize]byte
	k.auth(pk[:poly1305.KeySize], expectedTag[:], ciphertext, data)

	if subtle.ConstantTimeCompare(expectedTag[:], tag) != 1 {
		return nil, ErrAuthFailed
	}

	ret, out := sliceForAppend(dst, len(ciphertext))
	c.XORKeyStream(out, ciphertext)
	return ret, nil
}

type grower interface {
	Grow(n int)
}

type getSetBuffer interface {
	GetBuffer() interface{}
	SetBuffer(interface{})
}

var authPool = new(sync.Pool)

func (k *chacha20Key) auth(key, out, ciphertext, data []byte) {
	m, err := poly1305.New(key)
	if err != nil {
		panic(err)
	}

	if b, ok := m.(getSetBuffer); ok {
		b.SetBuffer(authPool.Get())
	}

	if k.draft {
		if g, ok := m.(grower); ok {
			g.Grow(len(data) + 8 + len(ciphertext) + 8)
		}

		m.Write(data)
		binary.Write(m, binary.LittleEndian, uint64(len(data)))

		m.Write(ciphertext)
		binary.Write(m, binary.LittleEndian, uint64(len(ciphertext)))
	} else {
		dPad := len(data) % poly1305PadLen
		if dPad != 0 {
			dPad = poly1305PadLen - dPad
		}

		cPad := len(ciphertext) % poly1305PadLen
		if cPad != 0 {
			cPad = poly1305PadLen - cPad
		}

		if g, ok := m.(grower); ok {
			g.Grow(len(data) + dPad + len(ciphertext) + cPad + 8 + 8)
		}

		var zero [poly1305PadLen-1]byte

		m.Write(data)
		m.Write(zero[:dPad])

		m.Write(ciphertext)
		m.Write(zero[:cPad])

		binary.Write(m, binary.LittleEndian, uint64(len(data)))
		binary.Write(m, binary.LittleEndian, uint64(len(ciphertext)))
	}

	m.Sum(out[:0])

	if b, ok := m.(getSetBuffer); ok {
		authPool.Put(b.GetBuffer())
	}

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
