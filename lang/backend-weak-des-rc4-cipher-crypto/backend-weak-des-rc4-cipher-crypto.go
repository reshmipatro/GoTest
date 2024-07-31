package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

func bad01() {
	// ruleid: backend-weak-des-rc4-cipher-crypto
	cipher, err := rc4.NewCipher([]byte("sekritz"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, len(plaintext))
	cipher.XORKeyStream(ciphertext, plaintext)
	fmt.Println("Secret message is:", hex.EncodeToString(ciphertext))
}

func bad02() {
	// ruleid: backend-weak-des-rc4-cipher-crypto
	block, err := des.NewCipher([]byte("sekritza"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
	fmt.Println("Secret message is:", hex.EncodeToString(ciphertext))
}

func bad03() {
	// ruleid: backend-weak-des-rc4-cipher-crypto
	block, err := des.NewTripleDESCipher([]byte("sekritzaaaaaaaaaaaaaaaaa"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, des.BlockSize+len(plaintext))
	iv := ciphertext[:des.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[des.BlockSize:], plaintext)
	fmt.Println("Secret message is:", hex.EncodeToString(ciphertext))
}

func bad04(filepath string) {
	file_content, err := os.ReadFile(filepath)
	if err != nil {
		panic(err)
	}
	// ruleid: backend-weak-des-rc4-cipher-crypto
	cipher, err := rc4.NewCipher([]byte("5uP3r5EcRe7"))
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, len(file_content))
	cipher.XORKeyStream(ciphertext, file_content)
	os.WriteFile(filepath, ciphertext, 0644)
}

func ok01() {
	// ok: backend-weak-des-rc4-cipher-crypto
	block, err := aes.NewCipher([]byte("32-bytes keyyyyyyyyyyyyyyyyyyyyy"))
	if err != nil {
		panic(err)
	}
	plaintext := []byte("I CAN HAZ SEKRIT MSG PLZ")
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	fmt.Println("Secret message is:", hex.EncodeToString(ciphertext))
}

func ok02(filepath string) {
	file_content, err := os.ReadFile(filepath)
	if err != nil {
		panic(err)
	}
	// highline-next-line
	c, err := aes.NewCipher([]byte("256-bits secret keyyyyyyyyyyyyyy"))
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(file_content))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], file_content)
	os.WriteFile(filepath, ciphertext, 0644)
}
