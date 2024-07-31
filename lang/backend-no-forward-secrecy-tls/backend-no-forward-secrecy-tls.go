package main

import "crypto/tls"

func main() {
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_RC4_128_SHA}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_128_CBC_SHA}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_256_CBC_SHA}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_128_CBC_SHA256}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_128_GCM_SHA256}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.CipherSuite{ID: tls.TLS_RSA_WITH_AES_256_GCM_SHA384}

	A := &tls.CipherSuite{}
	B := &tls.CipherSuite{}
	C := &tls.CipherSuite{}
	D := &tls.CipherSuite{}
	E := &tls.CipherSuite{}
	F := &tls.CipherSuite{}
	G := &tls.CipherSuite{}

	// ruleid: backend-no-forward-secrecy-tls
	A.ID = tls.TLS_RSA_WITH_RC4_128_SHA
	// ruleid: backend-no-forward-secrecy-tls
	B.ID = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	// ruleid: backend-no-forward-secrecy-tls
	C.ID = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-no-forward-secrecy-tls
	D.ID = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	// ruleid: backend-no-forward-secrecy-tls
	E.ID = tls.TLS_RSA_WITH_AES_128_CBC_SHA256
	// ruleid: backend-no-forward-secrecy-tls
	F.ID = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	// ruleid: backend-no-forward-secrecy-tls
	G.ID = tls.TLS_RSA_WITH_AES_256_GCM_SHA384

	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_RC4_128_SHA}}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA}}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_256_CBC_SHA}}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA256}}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_128_GCM_SHA256}}
	// ruleid: backend-no-forward-secrecy-tls
	_ = tls.Config{CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384}}

	a := tls.Config{}
	b := tls.Config{}
	c := tls.Config{}
	d := tls.Config{}
	e := tls.Config{}
	f := tls.Config{}
	g := tls.Config{}

	// ruleid: backend-no-forward-secrecy-tls
	a.CipherSuites = append(a.CipherSuites, tls.TLS_RSA_WITH_RC4_128_SHA)
	// ruleid: backend-no-forward-secrecy-tls
	b.CipherSuites = append(b.CipherSuites, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA)
	// ruleid: backend-no-forward-secrecy-tls
	c.CipherSuites = append(c.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA)
	// ruleid: backend-no-forward-secrecy-tls
	d.CipherSuites = append(d.CipherSuites, tls.TLS_RSA_WITH_AES_256_CBC_SHA)
	// ruleid: backend-no-forward-secrecy-tls
	e.CipherSuites = append(e.CipherSuites, tls.TLS_RSA_WITH_AES_128_CBC_SHA256)
	// ruleid: backend-no-forward-secrecy-tls
	f.CipherSuites = append(f.CipherSuites, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
	// ruleid: backend-no-forward-secrecy-tls
	g.CipherSuites = append(g.CipherSuites, tls.TLS_RSA_WITH_AES_256_GCM_SHA384)

	// ruleid: backend-no-forward-secrecy-tls
	a.CipherSuites[0] = tls.TLS_RSA_WITH_RC4_128_SHA
	// ruleid: backend-no-forward-secrecy-tls
	b.CipherSuites[0] = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	// ruleid: backend-no-forward-secrecy-tls
	c.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	// ruleid: backend-no-forward-secrecy-tls
	d.CipherSuites[0] = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	// ruleid: backend-no-forward-secrecy-tls
	e.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_CBC_SHA256
	// ruleid: backend-no-forward-secrecy-tls
	f.CipherSuites[0] = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	// ruleid: backend-no-forward-secrecy-tls
	g.CipherSuites[0] = tls.TLS_RSA_WITH_AES_256_GCM_SHA384
}
