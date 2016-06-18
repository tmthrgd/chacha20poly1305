# chacha20poly1305

[![GoDoc](https://godoc.org/github.com/tmthrgd/chacha20poly1305?status.svg)](https://godoc.org/github.com/tmthrgd/chacha20poly1305)
[![Build Status](https://travis-ci.org/tmthrgd/chacha20poly1305.svg?branch=master)](https://travis-ci.org/tmthrgd/chacha20poly1305)

An implementation of the chacha20poly1305 AEAD construction from
[draft-agl-tls-chacha20poly1305-03](http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03)
and [RFC7539](https://tools.ietf.org/html/rfc7539).

## Benchmark

```
BenchmarkDraftChaCha20Poly1305Codahale-8	     100	  11554288 ns/op	  90.75 MB/s	[codahale/chacha20poly1305]
BenchmarkRFCChaCha20Poly1305-8          	    2000	   1155191 ns/op	 907.71 MB/s	[tmthrgd/chacha20poly1305 - AVX only]
BenchmarkDraftChaCha20Poly1305-8        	    2000	   1185364 ns/op	 884.60 MB/s	[tmthrgd/chacha20poly1305 - AVX only]
BenchmarkAESGCM-8                       	    2000	    877037 ns/op	1195.59 MB/s	[crypto/aes crypto/cipher]
```

## License

Unless otherwise noted, the chacha20poly1305 source files are distributed under The MIT License found in the LICENSE file.
