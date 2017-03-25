# chacha20poly1305

[![GoDoc](https://godoc.org/github.com/tmthrgd/chacha20poly1305?status.svg)](https://godoc.org/github.com/tmthrgd/chacha20poly1305)
[![Build Status](https://travis-ci.org/tmthrgd/chacha20poly1305.svg?branch=master)](https://travis-ci.org/tmthrgd/chacha20poly1305)

**Deprecated**: This is a legacy implementation. New users should use
[x/crypto/chacha20poly1305](https://godoc.org/golang.org/x/crypto/chacha20poly1305) which exclusively implements
[RFC7539](https://tools.ietf.org/html/rfc7539).

An implementation of the chacha20poly1305 AEAD construction from
[draft-agl-tls-chacha20poly1305-03](http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03)
and [RFC7539](https://tools.ietf.org/html/rfc7539).

## Benchmark

```
BenchmarkDraftChaCha20Poly1305Codahale/1M-8         	     200	   8841226 ns/op	 118.60 MB/s	[codahale/chacha20poly1305]
BenchmarkRFCChaCha20Poly1305/1M-8                   	    2000	   1190440 ns/op	 880.83 MB/s	[tmthrgd/chacha20poly1305 - AVX only]
BenchmarkDraftChaCha20Poly1305/1M-8                 	    1000	   1219685 ns/op	 859.71 MB/s	[tmthrgd/chacha20poly1305 - AVX only]
BenchmarkXCryptoChaCha20Poly1305/1M-8               	    2000	   1071064 ns/op	 979.00 MB/s	[x/crypto/chacha20poly1305 - AVX only]
BenchmarkAESGCM/1M-8                                	    2000	    864059 ns/op	1213.55 MB/s	[crypto/aes crypto/cipher]
```

## License

Unless otherwise noted, the chacha20poly1305 source files are distributed under The MIT License found in the LICENSE file.
