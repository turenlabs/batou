package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the per-machine FileTaintCache HMAC key (graph/cache_trust.go)
// to a throwaway path for the scanner test binary. Without this, tests that
// exercise the negative-confirmation suppression path (which now requires a
// locally-signed cache entry) would depend on a writable real user-config dir,
// making them fragile in minimal CI environments — and would create a stray
// key file under the runner's home. Only set when the caller hasn't already
// pinned a key path.
func TestMain(m *testing.M) {
	cleanup := func() {}
	if os.Getenv("BATOU_CACHE_KEY_FILE") == "" {
		if dir, err := os.MkdirTemp("", "batou-scanner-cachekey-*"); err == nil {
			_ = os.Setenv("BATOU_CACHE_KEY_FILE", filepath.Join(dir, "cache_hmac.key"))
			cleanup = func() { _ = os.RemoveAll(dir) }
		}
	}
	code := m.Run()
	cleanup() // os.Exit skips defers, so clean up explicitly first.
	os.Exit(code)
}
