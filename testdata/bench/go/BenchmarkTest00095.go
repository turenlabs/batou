package bench

import (
	"net/http"
	"text/template"
)

// Fixed template via channel data
func Handler00095(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	ch := make(chan string, 1)
	ch <- name
	val := <-ch
	t, _ := template.New("t").Parse("Hello {{.}}")
	t.Execute(w, val)
}
