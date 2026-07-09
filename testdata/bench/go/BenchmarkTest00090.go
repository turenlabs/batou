package bench

import (
	"net/http"
	"text/template"
)

// Template injection via Cookie
func Handler00090(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("theme_template")
	t, _ := template.New("t").Parse(cookie.Value)
	t.Execute(w, nil)
}
