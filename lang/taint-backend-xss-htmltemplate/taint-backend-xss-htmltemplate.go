package main

import (
	"fmt"
	"html/template"
	"net/http"
)

const tpl = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>{{.Title}}</title>
	</head>
	<body>
		{{.Body}}
	</body>
</html>
`

func bad01(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(tpl))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ruleid: taint-backend-xss-htmltemplate
		"Body": template.HTML("<h1>" + req.FormValue("title") + "</h1>"),
	}
	t.Execute(w, v)
}

func bad02(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(""))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ruleid: taint-backend-xss-htmltemplate
		"Body": "<a " + template.HTMLAttr(fmt.Sprintf(`href="/%s"`, req.FormValue("href"))) + ">Click here</a>",
	}
	t.Execute(w, v)
}

func bad03(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(""))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ruleid: taint-backend-xss-htmltemplate
		"Body": "<a href=\"" + template.URL(req.FormValue("url")) + "\">Click here</a>",
	}
	t.Execute(w, v)
}

func bad04(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(""))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ruleid: taint-backend-xss-htmltemplate
		"Body": fmt.Sprintf(`<script>alert("%s")</script>`, template.JS(req.FormValue("msg"))),
	}
	t.Execute(w, v)
}

func ok01(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(""))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ok: taint-backend-xss-htmltemplate
		"Body": "<h1>This is test H1</h1>",
	}
	t.Execute(w, v)
}

func ok02(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(""))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ok: taint-backend-xss-htmltemplate
		"Body": template.HTMLEscapeString("<h1>" + req.FormValue("title") + "</h1>"),
	}
	t.Execute(w, v)
}

func ok03(w http.ResponseWriter, req *http.Request) {
	t := template.Must(template.New("ex").Parse(""))
	v := map[string]interface{}{
		"Title": "Test <b>World</b>",
		// ok: taint-backend-xss-htmltemplate
		"Body": fmt.Sprintf(`<script>alert("%s")</script>`, template.JSEscapeString(req.FormValue("msg"))),
	}
	t.Execute(w, v)
}
