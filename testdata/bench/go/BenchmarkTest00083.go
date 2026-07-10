package bench

import (
	"net/http"
	"text/template"
)

// Template injection via channel
func Handler00083(w http.ResponseWriter, r *http.Request) {
	input := r.FormValue("tpl")
	ch := make(chan string, 1)
	ch <- input
	tmplStr := <-ch
	t, _ := template.New("t").Parse(tmplStr)
	t.Execute(w, nil)
}
