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

func benchmarkDraftChaCha20Poly1305Codahale(b *testing.B, l int) {
	key := make([]byte, codahale.KeySize)
	c, _ := codahale.New(key)

	benchmarkAEAD(b, c, l)
}

func BenchmarkDraftChaCha20Poly1305Codahale_32(b *testing.B) {
	benchmarkDraftChaCha20Poly1305Codahale(b, 32)
}

func BenchmarkDraftChaCha20Poly1305Codahale_128(b *testing.B) {
	benchmarkDraftChaCha20Poly1305Codahale(b, 128)
}

func BenchmarkDraftChaCha20Poly1305Codahale_1k(b *testing.B) {
	benchmarkDraftChaCha20Poly1305Codahale(b, 1*1024)
}

func BenchmarkDraftChaCha20Poly1305Codahale_16k(b *testing.B) {
	benchmarkDraftChaCha20Poly1305Codahale(b, 16*1024)
}

func BenchmarkDraftChaCha20Poly1305Codahale_128k(b *testing.B) {
	benchmarkDraftChaCha20Poly1305Codahale(b, 128*1024)
}

func BenchmarkDraftChaCha20Poly1305Codahale_1M(b *testing.B) {
	benchmarkDraftChaCha20Poly1305Codahale(b, 1024*1024)
}

func benchmarkRFCChaCha20Poly1305(b *testing.B, l int) {
	key := make([]byte, KeySize)
	c, _ := NewRFC(key)

	benchmarkAEAD(b, c, l)
}

func BenchmarkRFCChaCha20Poly1305_32(b *testing.B) {
	benchmarkRFCChaCha20Poly1305(b, 32)
}

func BenchmarkRFCChaCha20Poly1305_128(b *testing.B) {
	benchmarkRFCChaCha20Poly1305(b, 128)
}

func BenchmarkRFCChaCha20Poly1305_1k(b *testing.B) {
	benchmarkRFCChaCha20Poly1305(b, 1*1024)
}

func BenchmarkRFCChaCha20Poly1305_16k(b *testing.B) {
	benchmarkRFCChaCha20Poly1305(b, 16*1024)
}

func BenchmarkRFCChaCha20Poly1305_128k(b *testing.B) {
	benchmarkRFCChaCha20Poly1305(b, 128*1024)
}

func BenchmarkRFCChaCha20Poly1305_1M(b *testing.B) {
	benchmarkRFCChaCha20Poly1305(b, 1024*1024)
}

func benchmarkDraftChaCha20Poly1305(b *testing.B, l int) {
	key := make([]byte, KeySize)
	c, _ := NewDraft(key)

	benchmarkAEAD(b, c, l)
}

func BenchmarkDraftChaCha20Poly1305_32(b *testing.B) {
	benchmarkDraftChaCha20Poly1305(b, 32)
}

func BenchmarkDraftChaCha20Poly1305_128(b *testing.B) {
	benchmarkDraftChaCha20Poly1305(b, 128)
}

func BenchmarkDraftChaCha20Poly1305_1k(b *testing.B) {
	benchmarkDraftChaCha20Poly1305(b, 1*1024)
}

func BenchmarkDraftChaCha20Poly1305_16k(b *testing.B) {
	benchmarkDraftChaCha20Poly1305(b, 16*1024)
}

func BenchmarkDraftChaCha20Poly1305_128k(b *testing.B) {
	benchmarkDraftChaCha20Poly1305(b, 128*1024)
}

func BenchmarkDraftChaCha20Poly1305_1M(b *testing.B) {
	benchmarkDraftChaCha20Poly1305(b, 1024*1024)
}

func benchmarkAESGCM(b *testing.B, l int) {
	key := make([]byte, 32)
	a, _ := aes.NewCipher(key)
	c, _ := cipher.NewGCM(a)

	benchmarkAEAD(b, c, l)
}

func BenchmarkAESGCM_32(b *testing.B) {
	benchmarkAESGCM(b, 32)
}

func BenchmarkAESGCM_128(b *testing.B) {
	benchmarkAESGCM(b, 128)
}

func BenchmarkAESGCM_1k(b *testing.B) {
	benchmarkAESGCM(b, 1*1024)
}

func BenchmarkAESGCM_16k(b *testing.B) {
	benchmarkAESGCM(b, 16*1024)
}

func BenchmarkAESGCM_128k(b *testing.B) {
	benchmarkAESGCM(b, 128*1024)
}

func BenchmarkAESGCM_1M(b *testing.B) {
	benchmarkAESGCM(b, 1024*1024)
}
