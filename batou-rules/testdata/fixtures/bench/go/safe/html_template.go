package safe

import (
	"html/template"
	"net/http"
)

var profileTmpl = template.Must(template.New("profile").Parse(`
<!DOCTYPE html>
<html>
<head><title>Profile</title></head>
<body>
  <h1>{{.Name}}</h1>
  <p>Email: {{.Email}}</p>
  <p>Bio: {{.Bio}}</p>
</body>
</html>
`))

type ProfileData struct {
	Name  string
	Email string
	Bio   string
}

// SAFE: html/template auto-escapes all interpolated values
func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	data := ProfileData{
		Name:  r.URL.Query().Get("name"),
		Email: r.URL.Query().Get("email"),
		Bio:   r.URL.Query().Get("bio"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	profileTmpl.Execute(w, data)
}

// SAFE: html/template with range (auto-escaped)
var listTmpl = template.Must(template.New("list").Parse(`
<ul>
{{range .Items}}<li>{{.}}</li>{{end}}
</ul>
`))

func ListHandler(w http.ResponseWriter, r *http.Request) {
	items := r.URL.Query()["item"]
	listTmpl.Execute(w, map[string][]string{"Items": items})
}
