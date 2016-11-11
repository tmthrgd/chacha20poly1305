// Copyright 2014 Coda Hale. All rights reserved.
// Use of this source code is governed by an MIT
// License that can be found in the LICENSE file.

package chacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"

	codahale "github.com/codahale/chacha20poly1305"
	"github.com/tmthrgd/chacha20"
	"github.com/tmthrgd/poly1305"
)

func mustHexDecode(v string) []byte {
	b, err := hex.DecodeString(v)
	if err != nil {
		panic(err)
	}

	return b
}

type testVector struct {
	key        []byte
	plaintext  []byte
	nonce      []byte
	data       []byte
	ciphertext []byte
}

// stolen from https://tools.ietf.org/html/rfc7539
var rfcTestVectors = []testVector{
	testVector{
		mustHexDecode("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"),
		mustHexDecode("496e7465726e65742d4472616674732061726520647261667420646f63756d65" +
			"6e74732076616c696420666f722061206d6178696d756d206f6620736978206d" +
			"6f6e74687320616e64206d617920626520757064617465642c207265706c6163" +
			"65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65" +
			"6e747320617420616e792074696d652e20497420697320696e617070726f7072" +
			"6961746520746f2075736520496e7465726e65742d4472616674732061732072" +
			"65666572656e6365206d6174657269616c206f7220746f206369746520746865" +
			"6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67" +
			"726573732e2fe2809d"),
		mustHexDecode("000000000102030405060708"),
		mustHexDecode("f33388860000000000004e91"),
		mustHexDecode("64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2" +
			"4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf" +
			"332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855" +
			"9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4" +
			"b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e" +
			"af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a" +
			"0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10" +
			"49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29" +
			"a6ad5cb4022b02709beead9d67890cbb22392336fea1851f38"),
	},
}

// stolen from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-02#section-7
var draftTestVectors = []testVector{
	testVector{
		mustHexDecode("4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007"),
		mustHexDecode("86d09974840bded2a5ca"),
		mustHexDecode("cd7cf67be39c794a"),
		mustHexDecode("87e229d4500845a079c0"),
		mustHexDecode("e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6"),
	},
}

func testSealing(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error), vectors []testVector) {
	for i, vector := range vectors {
		t.Run(fmt.Sprintf("vector%d", i), func(t *testing.T) {
			c, err := newChaCha20Poly1305(vector.key)
			if err != nil {
				t.Fatal(err)
			}

			actual := c.Seal(nil, vector.nonce, vector.plaintext, vector.data)

			if bytes.Equal(vector.ciphertext, actual) {
				return
			}

			t.Errorf("Bad seal: expected %x, was %x", vector.ciphertext, actual)

			for i, v := range vector.ciphertext {
				if actual[i] != v {
					t.Logf("Mismatch at offset %d: %x vs %x", i, v, actual[i])
					break
				}
			}
		})
	}
}

func TestRFCSealing(t *testing.T) {
	testSealing(t, NewRFC, rfcTestVectors)
}

func TestDraftSealing(t *testing.T) {
	testSealing(t, NewDraft, draftTestVectors)
}

func testOpening(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error), vectors []testVector) {
	for i, vector := range vectors {
		t.Run(fmt.Sprintf("vector%d", i), func(t *testing.T) {
			c, err := newChaCha20Poly1305(vector.key)
			if err != nil {
				t.Fatal(err)
			}

			actual, err := c.Open(nil, vector.nonce, vector.ciphertext, vector.data)
			if err != nil {
				t.Fatal(err)
			}

			if bytes.Equal(vector.plaintext, actual) {
				return
			}

			t.Errorf("Bad open: expected %x, was %x", vector.plaintext, actual)

			for i, v := range vector.plaintext {
				if actual[i] != v {
					t.Logf("Mismatch at offset %d: %x vs %x", i, v, actual[i])
					break
				}
			}
		})
	}
}

func TestRFCOpening(t *testing.T) {
	testOpening(t, NewRFC, rfcTestVectors)
}

func TestDraftOpening(t *testing.T) {
	testOpening(t, NewDraft, draftTestVectors)
}

func testRoundtrip(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error)) {
	key := make([]byte, KeySize)

	c, err := newChaCha20Poly1305(key)
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

func TestRFCRoundtrip(t *testing.T) {
	testRoundtrip(t, NewRFC)
}

func TestDraftRoundtrip(t *testing.T) {
	testRoundtrip(t, NewDraft)
}

func testModified(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error), modifyData bool) {
	key := make([]byte, KeySize)

	c, err := newChaCha20Poly1305(key)
	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	if modifyData {
		data[0] ^= 1
	} else {
		ciphertext[0] ^= 1
	}

	_, err = c.Open(nil, nonce, ciphertext, data)
	if err != ErrAuthFailed {
		t.Error("Should have failed, but didn't")
	}
}

func TestRFCModifiedData(t *testing.T) {
	testModified(t, NewRFC, true)
}

func TestDraftModifiedData(t *testing.T) {
	testModified(t, NewDraft, true)
}

func TestRFCModifiedCiphertext(t *testing.T) {
	testModified(t, NewRFC, false)
}

func TestDraftModifiedCiphertext(t *testing.T) {
	testModified(t, NewDraft, false)
}

func testNonceSize(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error), expect int) {
	key := make([]byte, KeySize)
	c, err := newChaCha20Poly1305(key)
	if err != nil {
		t.Error(err)
	}

	if c.NonceSize() != expect {
		t.Errorf("Expected nonce size of %d but was %d", expect, c.NonceSize())
	}
}

func TestRFCNonceSize(t *testing.T) {
	testNonceSize(t, NewRFC, chacha20.RFCNonceSize)
}

func TestDraftNonceSize(t *testing.T) {
	testNonceSize(t, NewDraft, chacha20.DraftNonceSize)
}

func testOverhead(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error)) {
	key := make([]byte, KeySize)
	c, err := newChaCha20Poly1305(key)
	if err != nil {
		t.Error(err)
	}

	if c.Overhead() != poly1305.TagSize {
		t.Errorf("Expected overhead of %d but was %d", poly1305.TagSize, c.Overhead())
	}
}

func TestRFCOverhead(t *testing.T) {
	testOverhead(t, NewRFC)
}

func TestDraftOverhead(t *testing.T) {
	testOverhead(t, NewDraft)
}

func testInvalidKey(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error)) {
	key := make([]byte, 31)
	_, err := newChaCha20Poly1305(key)

	if err != ErrInvalidKey {
		t.Errorf("Expected invalid key error but was %v", err)
	}
}

func TestRFCInvalidKey(t *testing.T) {
	testInvalidKey(t, NewRFC)
}

func TestDraftInvalidKey(t *testing.T) {
	testInvalidKey(t, NewDraft)
}

func testSealInvalidNonce(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error)) {
	key := make([]byte, KeySize)
	c, err := newChaCha20Poly1305(key)

	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize()-3)
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")

	defer func() {
		if r := recover(); r != ErrInvalidNonce {
			t.Errorf("Expected invalid key panic but was %v", r)
		}
	}()

	c.Seal(nil, nonce, plaintext, data)
}

func TestRFCSealInvalidNonce(t *testing.T) {
	testSealInvalidNonce(t, NewRFC)
}

func TestDraftSealInvalidNonce(t *testing.T) {
	testSealInvalidNonce(t, NewDraft)
}

func testOpenInvalidNonce(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error)) {
	key := make([]byte, KeySize)
	c, err := newChaCha20Poly1305(key)

	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	defer func() {
		if r := recover(); r != ErrInvalidNonce {
			t.Errorf("Expected invalid key panic but was %v", r)
		}
	}()

	c.Open(nil, nonce[:4], ciphertext, data)
}

func TestRFCOpenInvalidNonce(t *testing.T) {
	testOpenInvalidNonce(t, NewRFC)
}

func TestDraftOpenInvalidNonce(t *testing.T) {
	testOpenInvalidNonce(t, NewDraft)
}

func testOpenTooShort(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error)) {
	key := make([]byte, KeySize)
	c, err := newChaCha20Poly1305(key)

	if err != nil {
		t.Error(err)
	}

	nonce := make([]byte, c.NonceSize())
	plaintext := []byte("yay for me")
	data := []byte("whoah yeah")
	ciphertext := c.Seal(nil, nonce, plaintext, data)

	_, err = c.Open(nil, nonce, ciphertext[:2], data)

	if err != ErrAuthFailed {
		t.Errorf("Expected message authentication failed error but was %v", err)
	}
}

func TestRFCOpenTooShort(t *testing.T) {
	testOpenTooShort(t, NewRFC)
}

func TestDraftOpenTooShort(t *testing.T) {
	testOpenTooShort(t, NewDraft)
}

func testTagFailureOverwrite(t *testing.T, newChaCha20Poly1305 func(key []byte) (cipher.AEAD, error), vector testVector) {
	// The AESNI GCM code decrypts and authenticates concurrently and so
	// overwrites the output buffer before checking the authentication tag.
	// In order to be consistent across platforms, all implementations
	// should do this and this test checks that.

	c, err := newChaCha20Poly1305(vector.key)
	if err != nil {
		t.Error(err)
	}

	ct := append([]byte(nil), vector.ciphertext...)
	ct[len(ct)-1] ^= 1

	dst := make([]byte, len(ct))
	for i := range dst {
		dst[i] = 42
	}

	res, err := c.Open(dst[:0], vector.nonce, ct, vector.data)
	if err == nil {
		t.Fatal("Bad Open still resulted in nil error.")
	}

	if res != nil {
		t.Fatal("Failed Open returned non-nil result.")
	}

	for i := range dst[:len(res)] {
		if dst[i] != 0 {
			t.Fatal("Failed Open didn't zero dst buffer")
		}
	}
}

func TestRFCTagFailureOverwrite(t *testing.T) {
	testTagFailureOverwrite(t, NewRFC, rfcTestVectors[0])
}

func TestDraftTagFailureOverwrite(t *testing.T) {
	testTagFailureOverwrite(t, NewDraft, draftTestVectors[0])
}

func TestDraftEqual(t *testing.T) {
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
		MaxCountScale: 0.1,

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
