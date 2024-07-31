package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

func bad01(w http.Response, req *http.Request) {
	bigValue, err := strconv.Atoi(req.FormValue("num"))
	if err != nil {
		panic(err)
	}
	// ruleid: taint-backend-integer-overflow-strconv
	value := int32(bigValue)
	fmt.Println(value)
}

func bad02(w http.Response, req *http.Request) {
	bigValue, err := strconv.Atoi(req.FormValue("num"))
	if err != nil {
		panic(err)
	}
	// ruleid: taint-backend-integer-overflow-strconv
	value := int16(bigValue)
	fmt.Println(value)
}

func ok01(w http.Response, req *http.Request) {
	bigValue, err := strconv.ParseInt(req.FormValue("num"), 10, 32)
	if err != nil {
		panic(err)
	}
	// ok: taint-backend-integer-overflow-strconv
	value := int32(bigValue)
	fmt.Println(value)
}

func ok02(w http.Response, req *http.Request) {
	bigValue, err := strconv.ParseUint(req.FormValue("num"), 10, 32)
	if err != nil {
		panic(err)
	}
	// ok: taint-backend-integer-overflow-strconv
	value := int32(bigValue)
	fmt.Println(value)
}

func ok03(w http.Response, req *http.Request) {
	bigValue, err := strconv.ParseUint("12311123332", 10, 16)
	if err != nil {
		panic(err)
	}
	// ok: taint-backend-integer-overflow-strconv
	value := int16(bigValue)
	fmt.Println(value)
}

func ok04(w http.Response, req *http.Request) {
	type blockUserRequest struct {
		UserID string `json:"userId"`
		Age    int    `json:"enabled"`
	}

	decoder := json.NewDecoder(req.Body)
	var request blockUserRequest

	if err := decoder.Decode(&request); err != nil {
		panic(err)
	}
	// todoruleid: taint-backend-integer-overflow-strconv
	value := int32(request.Age)
	fmt.Println(value)
}

func main() {
	var i int
	var j int32

	i = 1 << 31
	j = int32(i)

	fmt.Printf("int: %v, int32: %v", i, j)
}
