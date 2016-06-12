// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package chacha20poly1305

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	ref "github.com/codahale/chacha20poly1305"
)

const benchSize = 1024 * 1024

func benchmarkAEAD(b *testing.B, c cipher.AEAD) {
	b.SetBytes(benchSize)

	input := make([]byte, benchSize)
	output := make([]byte, benchSize)
	nonce := make([]byte, c.NonceSize())

	for i := 0; i < b.N; i++ {
		c.Seal(output, nonce, input, nil)
	}
}

func BenchmarkChaCha20Poly1305Go(b *testing.B) {
	key := make([]byte, ref.KeySize)
	c, _ := ref.New(key)

	benchmarkAEAD(b, c)
}

func BenchmarkChaCha20Poly1305(b *testing.B) {
	key := make([]byte, KeySize)
	c, _ := New(key)

	benchmarkAEAD(b, c)
}

func BenchmarkAESGCM(b *testing.B) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(a)

	benchmarkAEAD(b, c)
}
