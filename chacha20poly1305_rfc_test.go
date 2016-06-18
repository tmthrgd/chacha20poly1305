// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tmthrgd/chacha20"
	"golang.org/x/crypto/poly1305"
)

// stolen from https://tools.ietf.org/html/rfc7539
var rfcTestVectors = []struct {
	key, plaintext, nonce, data, expected string
}{
	{
		"1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
		"496e7465726e65742d4472616674732061726520647261667420646f63756d65" +
			"6e74732076616c696420666f722061206d6178696d756d206f6620736978206d" +
			"6f6e74687320616e64206d617920626520757064617465642c207265706c6163" +
			"65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65" +
			"6e747320617420616e792074696d652e20497420697320696e617070726f7072" +
			"6961746520746f2075736520496e7465726e65742d4472616674732061732072" +
			"65666572656e6365206d6174657269616c206f7220746f206369746520746865" +
			"6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67" +
			"726573732e2fe2809d",
		"000000000102030405060708",
		"f33388860000000000004e91",
		"64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2" +
			"4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf" +
			"332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855" +
			"9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4" +
			"b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e" +
			"af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a" +
			"0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10" +
			"49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29" +
			"a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38",
	},
}

func TestRFCOpening(t *testing.T) {
	for i, vector := range rfcTestVectors {
		t.Logf("Running test vector %d", i)

		key, err := hex.DecodeString(vector.key)
		if err != nil {
			t.Error(err)
		}

		plaintext, err := hex.DecodeString(vector.plaintext)
		if err != nil {
			t.Error(err)
		}

		nonce, err := hex.DecodeString(vector.nonce)
		if err != nil {
			t.Error(err)
		}

		data, err := hex.DecodeString(vector.data)
		if err != nil {
			t.Error(err)
		}

		expected, err := hex.DecodeString(vector.expected)
		if err != nil {
			t.Error(err)
		}

		c, err := NewRFC(key)
		if err != nil {
			t.Error(err)
		}

		actual := c.Seal(nil, nonce, plaintext, data)

		if !bytes.Equal(expected, actual) {
			t.Errorf("Bad seal: expected %x, was %x", expected, actual)

			for i, v := range expected {
				if actual[i] != v {
					t.Logf("Mismatch at offset %d: %x vs %x", i, v, actual[i])
					break
				}
			}
		}
	}
}

func TestRFCRoundtrip(t *testing.T) {
	key := make([]byte, KeySize)

	c, err := NewRFC(key)
	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	actual, err := c.Open(nil, nonce, ciphertext, data)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(plaintext, actual) {
		t.Errorf("Bad seal: expected %x, was %x", plaintext, actual)
	}
}

func TestRFCModifiedData(t *testing.T) {
	key := make([]byte, KeySize)

	c, err := NewRFC(key)
	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	data[0] ^= 1

	_, err = c.Open(nil, nonce, ciphertext, data)
	if err != ErrAuthFailed {
		t.Error("Should have failed, but didn't")
	}
}

func TestRFCModifiedCiphertext(t *testing.T) {
	key := make([]byte, KeySize)

	c, err := NewRFC(key)
	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	ciphertext[0] ^= 1

	_, err = c.Open(nil, nonce, ciphertext, data)
	if err != ErrAuthFailed {
		t.Error("Should have failed, but didn't")
	}
}

func TestRFCNonceSize(t *testing.T) {
	key := make([]byte, KeySize)
	c, err := NewRFC(key)
	if err != nil {
		t.Error(err)
	}

	if c.NonceSize() != chacha20.RFCNonceSize {
		t.Errorf("Expected nonce size of %d but was %d", chacha20.RFCNonceSize, c.NonceSize())
	}
}

func TestRFCOverhead(t *testing.T) {
	key := make([]byte, KeySize)
	c, err := NewRFC(key)
	if err != nil {
		t.Error(err)
	}

	if c.Overhead() != poly1305.TagSize {
		t.Errorf("Expected overhead of %d but was %d", poly1305.TagSize, c.Overhead())
	}
}

func TestRFCInvalidKey(t *testing.T) {
	key := make([]byte, 31)
	_, err := NewRFC(key)

	if err != ErrInvalidKey {
		t.Errorf("Expected invalid key error but was %v", err)
	}
}

func TestRFCSealInvalidNonce(t *testing.T) {
	defer func() {
		if r := recover(); r != nil && r != ErrInvalidNonce {
			t.Errorf("Expected invalid key panic but was %v", r)
		}
	}()

	key := make([]byte, KeySize)
	c, err := NewRFC(key)

	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize()-3)
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	c.Seal(nil, nonce, plaintext, data)
}

func TestRFCOpenInvalidNonce(t *testing.T) {
	key := make([]byte, KeySize)
	c, err := NewRFC(key)

	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	_, err = c.Open(nil, nonce[0:4], ciphertext, data)

	if err != ErrInvalidNonce {
		t.Errorf("Expected invalid nonce error but was %v", err)
	}
}

func readSecretKey(i int) []byte {
	return make([]byte, i)
}

func readRandomNonce(i int) []byte {
	return make([]byte, i)
}

func ExampleNewRFC() {
	key := readSecretKey(KeySize) // must be 256 bits long

	c, err := NewRFC(key)
	if err != nil {
		panic(err)
	}

	nonce := readRandomNonce(c.NonceSize()) // must be generated by crypto/rand
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	fmt.Printf("%x\n", ciphertext)
}
