package main

import "crypto/tls"

func main() {
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_128_CBC_SHA}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_256_CBC_SHA}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}

	A := &tls.CipherSuite{}
	B := &tls.CipherSuite{}
	C := &tls.CipherSuite{}
	D := &tls.CipherSuite{}
	E := &tls.CipherSuite{}
	F := &tls.CipherSuite{}

	// ruleid: backend-weak-cbc-cipher-tls
	A.ID = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	B.ID = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	C.ID = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	D.ID = tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	E.ID = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	F.ID = tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA

	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_256_CBC_SHA}}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}
	// ruleid: backend-weak-cbc-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA}}

	a := tls.Config{}
	b := tls.Config{}
	c := tls.Config{}
	d := tls.Config{}
	e := tls.Config{}
	f := tls.Config{}

	// ruleid: backend-weak-cbc-cipher-tls
	a.CipherSuites = append(a.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	// ruleid: backend-weak-cbc-cipher-tls
	b.CipherSuites = append(b.CipherSuites, tls.TLS_RSA_WITH_AES_256_CBC_SHA)
	// ruleid: backend-weak-cbc-cipher-tls
	c.CipherSuites = append(c.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
	// ruleid: backend-weak-cbc-cipher-tls
	d.CipherSuites = append(d.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA)
	// ruleid: backend-weak-cbc-cipher-tls
	e.CipherSuites = append(e.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
	// ruleid: backend-weak-cbc-cipher-tls
	f.CipherSuites = append(f.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA)

	// ruleid: backend-weak-cbc-cipher-tls
	a.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	b.CipherSuites[0] = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	c.CipherSuites[0] = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	d.CipherSuites[0] = tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	e.CipherSuites[0] = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-weak-cbc-cipher-tls
	f.CipherSuites[0] = tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
}
