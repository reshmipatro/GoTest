package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/kennygrant/sanitize"
)

func bad0(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	// ruleid: taint-backend-path-traversal-write
	ioutil.WriteFile(file_path, []byte("bad data"), 0)
}

func bad1(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	// ruleid: taint-backend-path-traversal-write
	os.WriteFile(file_path, []byte("bad data"), 0)
}

func bad2(resp http.ResponseWriter, req *http.Request) {
	file, err := os.Open(req.URL.Query().Get("path"))
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}
	defer file.Close()

	// ruleid: taint-backend-path-traversal-write
	file.Write([]byte("bad data"))
}

func bad3(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.OpenFile(file_path, os.O_RDONLY, 0644)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	// ruleid: taint-backend-path-traversal-write
	file.WriteAt([]byte("bad data"), 0)
}

func bad4(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	// ruleid: taint-backend-path-traversal-write
	file.WriteString("bad data")
}

func bad5(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	reader := bytes.NewReader([]byte("bad data"))

	// ruleid: taint-backend-path-traversal-write
	io.Copy(file, reader)
}

func bad6(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	reader := bytes.NewReader([]byte("bad data"))

	// ruleid: taint-backend-path-traversal-write
	io.CopyN(file, reader, 1000)
}

func bad7(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	reader := bytes.NewReader([]byte("bad data"))

	var buffer [1024]byte
	// ruleid: taint-backend-path-traversal-write
	io.CopyBuffer(file, reader, buffer[:])
}

func UploadImage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseMultipartForm(32 << 20) // maxMemory
		if err != nil {
			fmt.Printf("%+v\n", err)
			return
		}

		if _, err := r.Cookie("SESSID"); err == nil {
			file, handler, err := r.FormFile("uploadfile")
			if err != nil {
				fmt.Printf("%+v\n", err)
				return
			}
			defer file.Close()
			// ruleid: taint-backend-path-traversal-write
			f, err := os.OpenFile("./assets/img/"+handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
			if err != nil {
				fmt.Printf("%+v\n", err)
				return
			}
			defer f.Close()
			// ruleid: taint-backend-path-traversal-write
			io.Copy(f, file)
			// UpdateDatabase(r, handler.Filename)

			http.Redirect(w, r, "/profile", 301)
		}
	} else {
		http.NotFound(w, nil)
	}

}

func sanitized0(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = path.Clean(file_path)
	// ok: taint-backend-path-traversal-write
	ioutil.WriteFile(file_path, []byte("bad data"), 0)
}

func sanitized1(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = path.Base(file_path)

	// ok: taint-backend-path-traversal-write
	os.WriteFile(file_path, []byte("bad data"), 0)
}

func sanitized2(resp http.ResponseWriter, req *http.Request) {
	file, err := os.Open(filepath.Clean(req.URL.Query().Get("path")))
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}
	defer file.Close()

	// ok: taint-backend-path-traversal-write
	file.Write([]byte("bad data"))
}

func sanitized3(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = filepath.Base(file_path)

	file, err := os.OpenFile(file_path, os.O_RDONLY, 0644)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	// ok: taint-backend-path-traversal-write
	file.WriteAt([]byte("bad data"), 0)
}

func sanitized4(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.BaseName(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	// ok: taint-backend-path-traversal-write
	file.WriteString("bad data")
}

func sanitized5(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.Name(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	reader := bytes.NewReader([]byte("bad data"))

	// ok: taint-backend-path-traversal-write
	io.Copy(file, reader)
}

func sanitized6(resp http.ResponseWriter, req *http.Request) {
	file_path := req.URL.Query().Get("path")
	file_path = sanitize.Path(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 500)
		return
	}

	reader := bytes.NewReader([]byte("bad data"))

	// ok: taint-backend-path-traversal-write
	io.CopyN(file, reader, 1000)
}

func good0(resp http.ResponseWriter, req *http.Request) {
	file_path := "./write"
	form_file, _, err := req.FormFile("file")

	if err != nil {
		http.Error(resp, "the form key 'file' is required and should contain a file", 400)
		return
	}

	file, err := os.Open(file_path)
	if err != nil {
		http.Error(resp, "Failed to open file", 400)
		return
	}

	var buffer [1024]byte
	// ok: taint-backend-path-traversal-write
	io.CopyBuffer(file, form_file, buffer[:])
}
