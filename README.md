# chacha20poly1305

[![GoDoc](https://godoc.org/github.com/tmthrgd/chacha20poly1305?status.svg)](https://godoc.org/github.com/tmthrgd/chacha20poly1305)
[![Build Status](https://travis-ci.org/tmthrgd/chacha20poly1305.svg?branch=master)](https://travis-ci.org/tmthrgd/chacha20poly1305)

An implementation of the chacha20poly1305 AEAD construction from
[draft-agl-tls-chacha20poly1305-03](http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-03).

## Benchmark

```
BenchmarkChaCha20Poly1305Go-8	     100	  11447803 ns/op	  91.60 MB/s	[codahale/chacha20poly1305]
BenchmarkChaCha20Poly1305-8  	     500	   3297028 ns/op	 318.04 MB/s	[tmthrgd/chacha20poly1305 - AVX only]
BenchmarkAESGCM-8            	    2000	    878952 ns/op	1192.98 MB/s	[crypto/aes crypto/cipher]
```

## License

Unless otherwise noted, the chacha20 source files are distributed under The MIT License found in the LICENSE file.
