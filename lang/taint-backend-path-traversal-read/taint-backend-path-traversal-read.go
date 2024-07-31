package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kennygrant/sanitize"
)

func bad0(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	// ruleid: taint-backend-path-traversal-read
	http.ServeFile(resp, req, file_path)
}

func bad1(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	data, err := ioutil.ReadFile(file_path)
	if err != nil {
		http.Error(resp, "Failed to read file", 404)
		return
	}

	// ruleid: taint-backend-path-traversal-read
	resp.Write(data)
}

func bad2(resp http.ResponseWriter, req *http.Request) {
	file, err := os.Open(req.URL.Query().Get("path"))
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
		return
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		http.Error(resp, "Failed to read file", 500)
		return
	}

	// ruleid: taint-backend-path-traversal-read
	http.Error(resp, string(contents), 200)
}

func bad3(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.OpenFile(file_path, os.O_RDONLY, 0644)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
		return
	}

	var fileData [4096]byte
	index := 0
	for {
		count, err := file.Read(fileData[index:])

		if err == io.EOF {
			break
		}

		if err != nil {
			http.Error(resp, "Failed to read file", 500)
			return
		}

		index += count
	}

	// todook: taint-backend-path-traversal-read
	http.SetCookie(resp, &http.Cookie{Name: "my-cookie", Value: string(fileData[:index])})
}

func bad4(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	contents, err := os.ReadFile(file_path)
	if err != nil {
		http.Error(resp, "Failed to read file", 404)
	}

	// ruleid: taint-backend-path-traversal-read
	http.ServeContent(resp, req, "A file", time.Now(), bytes.NewReader(contents))
}

func bad5(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	// ruleid: taint-backend-path-traversal-read
	io.Copy(resp, file)
}

func bad6(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	var buffer [1024]byte
	// ruleid: taint-backend-path-traversal-read
	io.CopyBuffer(resp, file, buffer[:])
}

func bad7(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	// ruleid: taint-backend-path-traversal-read
	io.CopyN(resp, file, 1024)
}

func bad8(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	contents, err := os.ReadFile(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	// ruleid: taint-backend-path-traversal-read
	io.WriteString(resp, string(contents))
}

func sanitized0(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = path.Clean(file_path)
	// ok: taint-backend-path-traversal-read
	http.ServeFile(resp, req, file_path)
}

func sanitized1(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = filepath.Clean(file_path)

	data, err := ioutil.ReadFile(file_path)
	if err != nil {
		http.Error(resp, "Failed to read file", 404)
		return
	}

	// ok: taint-backend-path-traversal-read
	resp.Write(data)
}

func sanitized2(resp http.ResponseWriter, req *http.Request) {
	file, err := os.Open(path.Base(req.URL.Query().Get("path")))
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
		return
	}
	defer file.Close()

	contents, err := io.ReadAll(file)
	if err != nil {
		http.Error(resp, "Failed to read file", 500)
		return
	}

	// ok: taint-backend-path-traversal-read
	http.Error(resp, string(contents), 200)
}

func sanitized3(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.OpenFile(file_path, os.O_RDONLY, 0644)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
		return
	}

	var fileData [4096]byte
	index := 0
	for {
		count, err := file.Read(fileData[index:])

		if err == io.EOF {
			break
		}

		if err != nil {
			http.Error(resp, "Failed to read file", 500)
			return
		}

		index += count
	}

	// todook: taint-backend-path-traversal-read
	http.SetCookie(resp, &http.Cookie{Name: "my-cookie", Value: string(fileData[:index])})
}

func sanitized4(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = filepath.Base(file_path)

	contents, err := os.ReadFile(file_path)
	if err != nil {
		http.Error(resp, "Failed to read file", 404)
	}

	// ok: taint-backend-path-traversal-read
	http.ServeContent(resp, req, "A file", time.Now(), bytes.NewReader(contents))
}

func sanitized5(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.BaseName(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	// ok: taint-backend-path-traversal-read
	io.Copy(resp, file)
}

func sanitized6(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.Name(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	var buffer [1024]byte
	// ok: taint-backend-path-traversal-read
	io.CopyBuffer(resp, file, buffer[:])
}

func sanitized7(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.Path(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	// ok: taint-backend-path-traversal-read
	io.CopyN(resp, file, 1024)
}

func sanitized8(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.Path(file_path)

	contents, err := os.ReadFile(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 404)
	}

	// ok: taint-backend-path-traversal-read
	io.WriteString(resp, string(contents))
}

func NotAFalsePositive(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")

	client := &http.Client{}
	resp, err := client.Get(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// ok: taint-backend-path-traversal-read
	w.Write(data)
}
