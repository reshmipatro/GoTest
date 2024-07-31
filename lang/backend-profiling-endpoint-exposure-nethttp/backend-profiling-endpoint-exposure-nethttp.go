package main

import (
	"fmt"
	"log"
	"net/http"

	// ruleid: backend-profiling-endpoint-exposure-nethttp
	_ "net/http/pprof"
)

func bad() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello World!")
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ^^^^^^^^^^^^^^^^
// COMMENT OUT TILL HERE

// -----------
// Please Read
// -----------
// Unfortunately, we can't have all tests in one file, and
// have them run at the same time. This is because we are trying
// to flag an `import` statement, which can only occur once per file.
//
// Somewhat annoyingly, semgrep only allows one test file per rule.
// To get around this, another 'file' has been left here. If you want
// to test the below case, uncomment it, and comment out the top half
// of the file.

// UNCOMMENT FROM HERE
// vvvvvvvvvvvvvvvvvvv
// package main
//
// import (
// 	"fmt"
// 	"log"
// 	"net/http"
//
// 	// ok: backend-profiling-endpoint-exposure-nethttp
// 	_ "net/http/pprof"
// )
//
// func good() {
// 	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Fprintf(w, "Hello World!")
// 	})
// 	log.Fatal(http.ListenAndServe("localhost", nil))
// }
