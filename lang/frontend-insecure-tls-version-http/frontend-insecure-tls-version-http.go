package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	fullyInline := &http.Client{}
	// ruleid: frontend-insecure-tls-version-http
	fullyInline.Transport = &http.Transport{TLSClientConfig: &tls.Config{MaxVersion: tls.VersionTLS11}}

	stretchedOut := tls.Config{MinVersion: tls.VersionTLS10}
	// ruleid: frontend-insecure-tls-version-http
	transport := &http.Transport{TLSClientConfig: &stretchedOut}
	_ = &http.Client{Transport: transport}

	assigned := &http.Transport{}
	// ruleid: frontend-insecure-tls-version-http
	assigned.TLSClientConfig.MinVersion = tls.VersionTLS10
	// ruleid: frontend-insecure-tls-version-http
	assigned.TLSClientConfig.MaxVersion = tls.VersionTLS11
}
