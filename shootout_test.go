// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package chacha20poly1305

import (
	"crypto/aes"
	"crypto/cipher"
	"testing"

	codahale "github.com/codahale/chacha20poly1305"
)

type size struct {
	name string
	l    int
}

var sizes = []size{
	{"32", 32},
	{"128", 128},
	{"1K", 1 * 1024},
	{"16K", 16 * 1024},
	{"128K", 128 * 1024},
	{"1M", 1024 * 1024},
}

func benchmarkAEAD(b *testing.B, c cipher.AEAD, l int) {
	input := make([]byte, l)
	output := make([]byte, 0, l+c.Overhead())
	nonce := make([]byte, c.NonceSize())

	b.SetBytes(int64(l))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Seal(output, nonce, input, nil)
	}
}

func BenchmarkDraftChaCha20Poly1305Codahale(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, codahale.KeySize)
			c, _ := codahale.New(key)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkRFCChaCha20Poly1305(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, KeySize)
			c, _ := NewRFC(key)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkDraftChaCha20Poly1305(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, KeySize)
			c, _ := NewDraft(key)

			benchmarkAEAD(b, c, size.l)
		})
	}
}

func BenchmarkAESGCM(b *testing.B) {
	for _, size := range sizes {
		b.Run(size.name, func(b *testing.B) {
			key := make([]byte, 32)
			a, _ := aes.NewCipher(key)
			c, _ := cipher.NewGCM(a)

			benchmarkAEAD(b, c, size.l)
		})
	}
}
