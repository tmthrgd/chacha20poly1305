// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	codahale "github.com/codahale/chacha20poly1305"
	"github.com/tmthrgd/chacha20"
	"golang.org/x/crypto/poly1305"
)

// stolen from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-02#section-7
var draftTestVectors = []struct {
	key, plaintext, nonce, data, expected string
}{
	{
		"4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007",
		"86d09974840bded2a5ca",
		"cd7cf67be39c794a",
		"87e229d4500845a079c0",
		"e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6",
	},
}

func TestDraftSealing(t *testing.T) {
	for i, vector := range draftTestVectors {
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

		c, err := NewDraft(key)
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

func TestDraftRoundtrip(t *testing.T) {
	key := make([]byte, KeySize)

	c, err := NewDraft(key)
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

func TestDraftModifiedData(t *testing.T) {
	key := make([]byte, KeySize)

	c, err := NewDraft(key)
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

func TestDraftModifiedCiphertext(t *testing.T) {
	key := make([]byte, KeySize)

	c, err := NewDraft(key)
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

func TestDraftNonceSize(t *testing.T) {
	key := make([]byte, KeySize)
	c, err := NewDraft(key)
	if err != nil {
		t.Error(err)
	}

	if c.NonceSize() != chacha20.DraftNonceSize {
		t.Errorf("Expected nonce size of %d but was %d", chacha20.DraftNonceSize, c.NonceSize())
	}
}

func TestDraftOverhead(t *testing.T) {
	key := make([]byte, KeySize)
	c, err := NewDraft(key)
	if err != nil {
		t.Error(err)
	}

	if c.Overhead() != poly1305.TagSize {
		t.Errorf("Expected overhead of %d but was %d", poly1305.TagSize, c.Overhead())
	}
}

func TestDraftInvalidKey(t *testing.T) {
	key := make([]byte, 31)
	_, err := NewDraft(key)

	if err != ErrInvalidKey {
		t.Errorf("Expected invalid key error but was %v", err)
	}
}

func TestDraftSealInvalidNonce(t *testing.T) {
	defer func() {
		if r := recover(); r != nil && r != ErrInvalidNonce {
			t.Errorf("Expected invalid key panic but was %v", r)
		}
	}()

	key := make([]byte, KeySize)
	c, err := NewDraft(key)

	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize()-3)
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	c.Seal(nil, nonce, plaintext, data)
}

func TestDraftOpenInvalidNonce(t *testing.T) {
	key := make([]byte, KeySize)
	c, err := NewDraft(key)

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

func TestEqual(t *testing.T) {
	t.Parallel()

	if err := quick.CheckEqual(func(key, nonce, ptxt, data []byte) ([]byte, error) {
		c, err := codahale.New(key)
		if err != nil {
			return nil, err
		}

		return c.Seal(nil, nonce, ptxt, data), nil
	}, func(key, nonce, ptxt, data []byte) ([]byte, error) {
		c, err := NewDraft(key)
		if err != nil {
			return nil, err
		}

		return c.Seal(nil, nonce, ptxt, data), nil
	}, &quick.Config{
		Values: func(args []reflect.Value, rand *rand.Rand) {
			key := make([]byte, KeySize)
			rand.Read(key)
			args[0] = reflect.ValueOf(key)

			nonce := make([]byte, chacha20.DraftNonceSize)
			rand.Read(nonce)
			args[1] = reflect.ValueOf(nonce)

			ptxt := make([]byte, 1+rand.Intn(1024*1024))
			rand.Read(ptxt)
			args[2] = reflect.ValueOf(ptxt)

			data := make([]byte, 1+rand.Intn(1024*1024))
			rand.Read(data)
			args[3] = reflect.ValueOf(data)
		},
	}); err != nil {
		t.Error(err)
	}
}

func ExampleNewDraft() {
	key := readSecretKey(KeySize) // must be 256 bits long

	c, err := NewDraft(key)
	if err != nil {
		panic(err)
	}

	nonce := readRandomNonce(c.NonceSize()) // must be generated by crypto/rand
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	fmt.Printf("%x\n", ciphertext)
	// Output: e6669e9e333e4a5af5df2b8d1669cbdc175bb32da46484e6e358
}
