package bench

import (
	"net/http"
	"text/template"
)

// Template from file, data from user
func Handler00094(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	t, _ := template.ParseFiles("templates/page.html")
	t.Execute(w, map[string]string{"Name": name})
}
