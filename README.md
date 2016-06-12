# chacha20poly1305

[![GoDoc](https://godoc.org/github.com/tmthrgd/chacha20poly1305?status.svg)](https://godoc.org/github.com/tmthrgd/chacha20poly1305)
[![Build Status](https://travis-ci.org/tmthrgd/chacha20poly1305.svg?branch=master)](https://travis-ci.org/tmthrgd/chacha20poly1305)

An implementation of the chacha20poly1305 AEAD construction from
[draft-agl-tls-chacha20poly1305-03](http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03).

## Benchmark

```
BenchmarkChaCha20Poly1305Go-8	     100	  11968525 ns/op	  87.61 MB/s	[codahale/chacha20poly1305]
BenchmarkChaCha20Poly1305-8  	     300	   3505448 ns/op	 299.13 MB/s	[tmthrgd/chacha20poly1305 - AVX only]
BenchmarkAESGCM-8            	    1000	   1871466 ns/op	 560.30 MB/s	[crypto/aes crypto/cipher]
```

## License

Unless otherwise noted, the chacha20 source files are distributed under The MIT License found in the LICENSE file.
