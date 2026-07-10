package bench

import (
	"net/http"
	"os"
)

// Hardcoded remove with defer
func Handler00059(w http.ResponseWriter, r *http.Request) {
	_ = r.FormValue("ignored")
	defer os.Remove("/tmp/cleanup.tmp")
}
