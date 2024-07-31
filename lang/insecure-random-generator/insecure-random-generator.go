package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"math/rand"
	"net/http"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type User struct {
	ID        uint `gorm:"primaryKey"`
	FirstName string
	LastName  string
	Age       uint
}

func test_http(resp http.ResponseWriter, req *http.Request) {
	var randBytes [64]byte
	rand.Read(randBytes[:])

	oneTimeLink := fmt.Sprintf("/reset&token=%v", base64.URLEncoding.EncodeToString(randBytes[:]))
	// ruleid: insecure-random-generator
	http.Redirect(resp, req, oneTimeLink, http.StatusTemporaryRedirect)
}

func test_certs() {
	// ruleid: insecure-random-generator
	cert := x509.Certificate{SerialNumber: big.NewInt(rand.Int63())}
	myInt := big.NewInt(rand.Int63())

	// ruleid: insecure-random-generator
	cert.SerialNumber = myInt
}

func test_db() {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Migrate the schema
	db.AutoMigrate(&User{})

	// ruleid: insecure-random-generator
	db.Create(&User{ID: uint(rand.Uint64()), FirstName: "John", LastName: "Cena"})

	// Read
	var user User
	db.First(&user, 1) // find product with integer primary key

	// ruleid: insecure-random-generator
	db.Model(&user).Update("ID", uint(rand.Uint64()))
	// ruleid: insecure-random-generator
	db.Model(&user).Updates(User{FirstName: "Bob", LastName: "Ross", ID: uint(rand.Uint64())}) // non-zero fields
	// ruleid: insecure-random-generator
	db.Model(&user).Updates(map[string]interface{}{"ID": uint(rand.Uint64())})

	// Delete - delete product
	db.Delete(&user, 1)
}
