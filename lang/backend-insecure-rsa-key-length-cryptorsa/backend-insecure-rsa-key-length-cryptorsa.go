package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

var RSABITS = 512

func bad01() {
	// ruleid: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}
func bad02() {
	// ruleid: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateKey(rand.Reader, RSABITS)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}
func bad03() {
	// ruleid: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 5, 1024)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}
func bad04() {
	var bits = 1024
	// ruleid: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 5, bits)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}

func ok01() {
	// ok: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}

var SECURE_RSABITS = 2048

func ok02() {
	// ok: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateKey(rand.Reader, SECURE_RSABITS)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}
func ok03() {
	// ok: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 5, 2048)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}
func ok04() {
	var bits = 2048
	// ok: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 5, bits)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}

func todo01() {
	bits := context.Background().Value("rsa-length").(int)
	// todoruleid: backend-insecure-rsa-key-length-cryptorsa
	pvk, err := rsa.GenerateMultiPrimeKey(rand.Reader, 5, bits)
	if err != nil {
		panic(err)
	}
	fmt.Println(pvk)
}
