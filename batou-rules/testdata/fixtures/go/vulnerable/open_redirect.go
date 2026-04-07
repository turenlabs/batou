package vulnerable

import (
	"net/http"
)

// VULN: Open redirect - user controls the redirect destination URL.
// Should trigger taint analysis for go.http.redirect sink with user input source.

func HandleRedirect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")

	http.Redirect(w, r, target, http.StatusFound)
}

func HandleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")

	// Authenticate user ...
	// Then redirect to the return URL without validation
	http.Redirect(w, r, returnTo, 302)
}
