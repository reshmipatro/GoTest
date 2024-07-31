package main

import "net/http"

const userID string = "10"

func main() {
	// ruleid: backend-exposed-directory-http
	http.FileServer(http.Dir("/"))
	// ruleid: backend-exposed-directory-http
	http.FileServer(http.Dir("/etc"))
	// ruleid: backend-exposed-directory-http
	http.FileServer(http.Dir("/var/logs"))
	// ruleid: backend-exposed-directory-http
	http.FileServer(http.Dir("/usr/libs"))
	// ruleid: backend-exposed-directory-http
	http.FileServer(http.Dir("/proc"))

	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/srv"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/var/www"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/var/lib"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/usr/share"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/srv/uploads"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/var/www/static_html"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/var/lib/users/" + userID + "/uploads"))
	// ok: backend-exposed-directory-http
	http.FileServer(http.Dir("/usr/share/docs/static"))
}
