package test

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func bad01(w http.ResponseWriter, req *http.Request) {
	url := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad02(w http.ResponseWriter, req *http.Request) {
	url := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.Head(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad03(w http.ResponseWriter, req *http.Request) {
	url := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.Post(url, "", strings.NewReader("abc=123"))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad04(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.PostForm(u, url.Values{"key": {"value"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad05(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.DefaultClient.Get(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad06(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.DefaultClient.Post(u, "", strings.NewReader("abc=123"))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad07(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.DefaultClient.Head(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad08(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := http.DefaultClient.PostForm(u, url.Values{"key": {"value"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad09(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	client := &http.Client{}
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.Get(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad10(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	client := &http.Client{}
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.Head(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad11(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	client := &http.Client{}
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.Post(u, "", strings.NewReader("abc=123"))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad12(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	client := &http.Client{}
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.PostForm(u, url.Values{"key": {"value"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad13(w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	client := &http.Client{}
	// ruleid: taint-backend-ssrf-nethttp
	req, _ = http.NewRequest("GET", u, nil)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad14(client *http.Client, w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.Get(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad15(client *http.Client, w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.Head(u)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad16(client *http.Client, w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.Post(u, "", strings.NewReader("abc=123"))
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad17(client *http.Client, w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	resp, err := client.PostForm(u, url.Values{"key": {"value"}})
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad18(client *http.Client, w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	req, _ = http.NewRequest("GET", u, nil)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func bad19(client *http.Client, w http.ResponseWriter, req *http.Request) {
	u := req.FormValue("url")
	// ruleid: taint-backend-ssrf-nethttp
	req, _ = http.NewRequestWithContext(context.Background(), "GET", u, nil)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func ok01(w http.ResponseWriter, req *http.Request) {
	// ok: taint-backend-ssrf-nethttp
	resp, err := http.Get("http://localhost:1337")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func ok02(w http.ResponseWriter, req *http.Request) {
	client := &http.Client{}
	// ok: taint-backend-ssrf-nethttp
	resp, err := client.Get("http://localhost:1337")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func ok03(client *http.Client, w http.ResponseWriter, req *http.Request) {
	req, _ = http.NewRequest("GET", "http://localhost:1337", nil)
	// ok: taint-backend-ssrf-nethttp
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}

func ok04(client *http.Client, w http.ResponseWriter, req *http.Request) {
	req, _ = http.NewRequestWithContext(context.Background(), "GET", "http://localhost:1337", nil)
	// ok: taint-backend-ssrf-nethttp
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
}
