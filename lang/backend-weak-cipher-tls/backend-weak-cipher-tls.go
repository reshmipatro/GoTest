package main

import "crypto/tls"

func main() {
	// ruleid: backend-weak-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_RC4_128_SHA}
	// ruleid: backend-weak-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}
	// ruleid: backend-weak-cipher-tls
	_ = tls.CipherSuite{ID: tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}

	A := &tls.CipherSuite{}
	D := &tls.CipherSuite{}
	E := &tls.CipherSuite{}

	// ruleid: backend-weak-cipher-tls
	A.ID = tls.TLS_RSA_WITH_RC4_128_SHA
	// ruleid: backend-weak-cipher-tls
	D.ID = tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	// ruleid: backend-weak-cipher-tls
	E.ID = tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA

	// ruleid: backend-weak-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_RC4_128_SHA}}
	// ruleid: backend-weak-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA}}
	// ruleid: backend-weak-cipher-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA}}

	a := tls.Config{}
	b := tls.Config{}
	c := tls.Config{}
	d := tls.Config{}
	e := tls.Config{}
	f := tls.Config{}
	g := tls.Config{}

	// ruleid: backend-weak-cipher-tls
	a.CipherSuites = append(a.CipherSuites, tls.TLS_RSA_WITH_RC4_128_SHA)
	// ruleid: backend-weak-cipher-tls
	d.CipherSuites = append(d.CipherSuites, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA)
	// ruleid: backend-weak-cipher-tls
	e.CipherSuites = append(e.CipherSuites, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA)

	// ruleid: backend-weak-cipher-tls
	a.CipherSuites[0] = tls.TLS_RSA_WITH_RC4_128_SHA
	// ruleid: backend-weak-cipher-tls
	d.CipherSuites[0] = tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	// ruleid: backend-weak-cipher-tls
	e.CipherSuites[0] = tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA
}
