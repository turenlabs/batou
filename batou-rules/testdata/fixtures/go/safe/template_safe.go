package safe

import (
	"html/template"
	"net/http"
)

// SAFE: html/template auto-escapes user input, preventing XSS.
// Should NOT trigger template injection or XSS rules.

var profileTmpl = template.Must(template.New("profile").Parse(`
<!DOCTYPE html>
<html>
<head><title>Profile</title></head>
<body>
	<h1>Hello, {{.Name}}!</h1>
	<p>Email: {{.Email}}</p>
</body>
</html>
`))

type ProfileData struct {
	Name  string
	Email string
}

func HandleProfile(w http.ResponseWriter, r *http.Request) {
	data := ProfileData{
		Name:  r.FormValue("name"),
		Email: r.FormValue("email"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	profileTmpl.Execute(w, data)
}
