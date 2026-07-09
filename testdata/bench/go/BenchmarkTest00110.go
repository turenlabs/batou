package bench

import (
	"fmt"
	"net/http"
)

// XSS via Cookie reflection
func Handler00110(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("prefs")
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<script>var prefs='%s'</script>", cookie.Value)
}
