package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Modern Go crypto / path / safety sanitizer tests.
//
// Validates that the new sanitizer entries (PBKDF2, SHA-3, BLAKE2b/2s,
// Curve25519 X25519, NaCl secretbox/box, filepath.Localize, safehtml)
// are registered and clear taint along the expected paths.
// =========================================================================

func TestCatalogMatcher_ModernCryptoSanitizersRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sanitizers := cat.Sanitizers()
	matcher := NewCatalogMatcher(nil, nil, sanitizers, nil)

	expected := map[string]string{
		"go.crypto.pbkdf2.key":     "Key",
		"go.crypto.sha3":           "Sum256",
		"go.crypto.blake2b":        "Sum256",
		"go.crypto.blake2s":        "Sum256",
		"go.crypto.curve25519":     "X25519",
		"go.crypto.nacl.secretbox": "Seal",
		"go.crypto.nacl.box":       "Seal",
		"go.filepath.localize":     "Localize",
		"go.safehtml.htmlescaped":  "HTMLEscaped",
	}

	for id, method := range expected {
		found := false
		for _, s := range matcher.sanitizersByMethod[method] {
			if s.ID == id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected sanitizer %q to be indexed by method %q", id, method)
		}
	}
}

func TestAnalyzeGo_PBKDF2_SanitizesPasswordHashing(t *testing.T) {
	code := `package main

import (
	"crypto/sha256"
	"net/http"

	"golang.org/x/crypto/pbkdf2"
)

func handler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	salt := []byte("static-salt-for-test")
	derived := pbkdf2.Key([]byte(password), salt, 600000, 32, sha256.New)
	storeHash(derived)
}

func storeHash(b []byte) {}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("expected NO crypto sink flow when pbkdf2.Key is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SHA3_SanitizesHashing(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/sha3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	digest := sha3.Sum256([]byte(body))
	store(digest[:])
}

func store(b []byte) {}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("expected NO crypto sink flow when sha3.Sum256 is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_Blake2b_SanitizesHashing(t *testing.T) {
	code := `package main

import (
	"net/http"

	"golang.org/x/crypto/blake2b"
)

func handler(w http.ResponseWriter, r *http.Request) {
	body := r.FormValue("body")
	digest := blake2b.Sum256([]byte(body))
	store(digest[:])
}

func store(b []byte) {}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("expected NO crypto sink flow when blake2b.Sum256 is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_FilepathLocalize_SanitizesPath(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"path/filepath"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("file")
	clean, err := filepath.Localize(name)
	if err != nil {
		return
	}
	data, _ := os.ReadFile(clean)
	_ = data
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Errorf("expected NO file read flow when filepath.Localize is used; got id=%s", f.Sink.ID)
		}
	}
}

func TestAnalyzeGo_SafeHTMLEscaped_SanitizesHTML(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"

	"github.com/google/safehtml"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safe := safehtml.HTMLEscaped(name)
	fmt.Fprintf(w, "<h1>Hello, %s</h1>", safe)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTML output flow when safehtml.HTMLEscaped is used; got id=%s", f.Sink.ID)
		}
	}
}

// Negative regression: ensure we still detect an unsafe SHA-1 hash even
// though we added new modern hash sanitizers (no over-broad sanitizing).
func TestAnalyzeGo_ModernSanitizers_NoFalseSanitization(t *testing.T) {
	code := `package main

import (
	"crypto/sha1"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	digest := sha1.Sum([]byte(password))
	storeHash(digest[:])
}

func storeHash(b []byte) {}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	// We do NOT assert a specific flow here — the point is the new
	// modern-crypto sanitizers (pbkdf2/sha3/blake2 etc.) must not
	// accidentally fire on sha1.Sum and clear taint.
	for _, f := range flows {
		san := false
		for _, s := range f.Steps {
			if s.Description != "" && (containsAny(s.Description, []string{
				"sanitized by pbkdf2.Key",
				"sanitized by sha3.",
				"sanitized by blake2b.",
				"sanitized by blake2s.",
				"sanitized by curve25519.X25519",
				"sanitized by secretbox.Seal",
				"sanitized by box.Seal",
				"sanitized by filepath.Localize",
				"sanitized by safehtml.HTMLEscaped",
			})) {
				san = true
			}
		}
		if san {
			t.Errorf("modern sanitizer fired on sha1.Sum path (over-broad match); flow=%s", f.Sink.ID)
		}
	}
}

func containsAny(s string, needles []string) bool {
	for _, n := range needles {
		if len(s) >= len(n) {
			for i := 0; i+len(n) <= len(s); i++ {
				if s[i:i+len(n)] == n {
					return true
				}
			}
		}
	}
	return false
}
