package main

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/sha3"
)

func newMd5ToFile() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	defer func() {
		err := f.Close()
		if err != nil {
			log.Printf("error closing the file: %s", err)
		}
	}()
	// ruleid: backend-weak-hash-functions-crypto
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x", h.Sum(nil))
}

func newSha1ToFile() {
	f, err := os.Open("file.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	// ruleid: backend-weak-hash-functions-crypto
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x", h.Sum(nil))
}

func printMd5SumFromFile() {
	dat, err := os.ReadFile("/etc/passwd")
	if err != nil {
		panic(err)
	}
	// ruleid: backend-weak-hash-functions-crypto
	fmt.Printf("%x", md5.Sum(dat))
}

func printShaSumFromFile() {
	dat, err := os.ReadFile("/etc/passwd")
	if err != nil {
		panic(err)
	}
	// ruleid: backend-weak-hash-functions-crypto
	fmt.Printf("%x", sha1.Sum(dat))
}

func printSha3SumFromFileViaQueryString(w http.ResponseWriter, req *http.Request) {
	dat, err := os.ReadFile(req.URL.Query().Get("file"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-weak-hash-functions-crypto
	w.Write([]byte(fmt.Sprintf("%x", sha3.Sum256(dat))))
}
