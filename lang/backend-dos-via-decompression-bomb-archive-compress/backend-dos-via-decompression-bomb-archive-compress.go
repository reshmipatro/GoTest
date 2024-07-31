package main

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func bad01(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := gzip.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad02(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := zlib.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad03(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := bzip2.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func bad04(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := flate.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad05(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := lzw.NewReader(file, lzw.LSB, 8)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad06(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := tar.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func bad07(w http.ResponseWriter, req *http.Request) {
	file, fheader, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	reader, err := zip.NewReader(file, fheader.Size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		// ruleid: backend-dos-via-decompression-bomb-archive-compress
		io.Copy(os.Stdout, rc)
		rc.Close()
	}
}

func bad08(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := gzip.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad09(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := zlib.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad10(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := bzip2.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func bad12(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := flate.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad13(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := lzw.NewReader(file, lzw.LSB, 8)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func bad14(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := tar.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func bad15(w http.ResponseWriter, req *http.Request) {
	file, fheader, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	reader, err := zip.NewReader(file, fheader.Size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		buf := make([]byte, 8)
		// ruleid: backend-dos-via-decompression-bomb-archive-compress
		_, err = io.CopyBuffer(os.Stdout, rc, buf)
		rc.Close()
	}
}

func bad16(w http.ResponseWriter, req *http.Request) {
	var compressionDict = "->" +
		"<-" +
		"--" +
		"<->"

	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := flate.NewReaderDict(file, []byte(compressionDict))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func bad17(w http.ResponseWriter, req *http.Request) {
	var compressionDict = "->" +
		"<-" +
		"--" +
		"<->"

	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := zlib.NewReaderDict(file, []byte(compressionDict))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func bad18(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	r, err := zlib.NewReader(file)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	buf := make([]byte, 8)
	// ruleid: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyBuffer(os.Stdout, r, buf)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	r.Close()
}

func ok01(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := gzip.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func ok02(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := zlib.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func ok03(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := bzip2.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func ok04(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := flate.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func ok05(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := lzw.NewReader(file, lzw.LSB, 8)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r.Close()
}

func ok06(w http.ResponseWriter, req *http.Request) {
	file, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r := tar.NewReader(file)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func ok07(w http.ResponseWriter, req *http.Request) {
	file, fheader, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	reader, err := zip.NewReader(file, fheader.Size)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		// ok: backend-dos-via-decompression-bomb-archive-compress
		io.CopyN(os.Stdout, rc, 1024)
		rc.Close()
	}
}

func ok08(w http.ResponseWriter, req *http.Request) {
	src, _, err := req.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	r, err := zlib.NewReader(src)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	dest, err := os.Open("/tmp/decompression")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	written, err := io.CopyN(dest, r, 2*1024*1024)
	if err != nil {
		if written == 2*1024*1024 && err != io.EOF {
			http.Error(w, "Exceed archive file size limitation!", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
	dest.Close()
	r.Close()
}

func ok09(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	r, err := zlib.NewReader(file)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	// ok: backend-dos-via-decompression-bomb-archive-compress
	_, err = io.CopyN(os.Stdout, r, 1024)
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
	}
	r.Close()
}
