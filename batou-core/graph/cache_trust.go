package graph

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// The FileTaintCache "taint-clean" verdict is used to SUPPRESS regex-only
// findings (negative confirmation, see scanner.SuppressRegexWhenTaintClean).
// That makes the persisted call graph a suppression oracle: an attacker who
// ships a crafted .batou/callgraph.json in a repository could mark real
// vulnerabilities as taint-clean (FlowCount == 0 with a matching FNV content
// hash, which is trivially computable from the repo's own files) and silence
// the regex layer wholesale.
//
// The defense is to bind each clean verdict to a per-machine secret the
// attacker does not have. Cache entries are HMAC-signed with a key generated
// once and stored OUTSIDE any scanned repository (the user config dir). A
// verdict is only trusted for suppression when its signature verifies under
// the local key, so a repo-shipped entry (signed with a foreign key, or not
// signed at all) can never hide a finding.
//
// This gates SUPPRESSION only. Positive detection — cross-file edges, taint
// signatures, active-taint findings — is never affected by the signature, so
// a graph legitimately shared across machines still contributes all of its
// detections; it just cannot import another machine's authority to remove
// findings. If no key is available (e.g. a read-only home dir), signing and
// verification both fail closed: entries stay unsigned and are simply not
// trusted for suppression — the safe direction (keep findings), never the
// unsafe one (hide them).

var (
	cacheKeyMu   sync.Mutex
	cacheKey     []byte // nil when unavailable
	cacheKeyInit bool
)

// cacheKeyPath returns the on-disk location of the local HMAC key. Honors
// BATOU_CACHE_KEY_FILE for tests and unusual layouts; otherwise uses the
// user config dir (never a path inside a scanned repo).
func cacheKeyPath() (string, error) {
	if p := os.Getenv("BATOU_CACHE_KEY_FILE"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		// Fall back to the home dir; UserConfigDir can be unset in minimal
		// environments.
		home, herr := os.UserHomeDir()
		if herr != nil || home == "" {
			return "", fmt.Errorf("no config or home dir for cache key")
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "batou", "cache_hmac.key"), nil
}

// localCacheKey returns the per-machine HMAC key, generating and persisting a
// fresh 32-byte key on first use. Returns nil when no key can be read or
// created; callers treat nil as "no suppression authority". The result is
// cached for the process lifetime (guarded by cacheKeyMu).
func localCacheKey() []byte {
	cacheKeyMu.Lock()
	defer cacheKeyMu.Unlock()
	if cacheKeyInit {
		return cacheKey
	}
	cacheKeyInit = true
	cacheKey = loadOrCreateCacheKey()
	return cacheKey
}

// loadOrCreateCacheKey reads the on-disk key, generating and persisting a new
// one when absent or malformed. Returns nil on any unrecoverable error.
func loadOrCreateCacheKey() []byte {
	path, err := cacheKeyPath()
	if err != nil {
		return nil
	}
	// Existing key wins.
	if data, rerr := os.ReadFile(path); rerr == nil {
		if key, derr := hex.DecodeString(string(trimSpace(data))); derr == nil && len(key) == 32 {
			return key
		}
		// Malformed key file: fall through and regenerate.
	}
	key := make([]byte, 32)
	if _, rerr := rand.Read(key); rerr != nil {
		return nil
	}
	if merr := os.MkdirAll(filepath.Dir(path), 0o700); merr != nil {
		return nil
	}
	// 0600: readable only by the owner — this is a local secret.
	if werr := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); werr != nil {
		// Could not persist; still use the in-memory key for this process so
		// same-run writes/reads remain consistent.
		return key
	}
	return key
}

// trimSpace trims surrounding ASCII whitespace/newlines from a key file's
// bytes without pulling in strings for a hot-path-irrelevant helper.
func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpaceByte(b[start]) {
		start++
	}
	for end > start && isSpaceByte(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// signFileTaintCache returns the hex HMAC-SHA256 of the cache tuple under the
// local key, or "" when no key is available.
func signFileTaintCache(path string, contentHash uint64, flowCount int) string {
	key := localCacheKey()
	if key == nil {
		return ""
	}
	return signWithKey(key, path, contentHash, flowCount)
}

// signWithKey computes the cache-tuple HMAC under an explicit key. Split out
// so the trust logic has one canonical serialization and tests can exercise
// foreign-key signatures.
func signWithKey(key []byte, path string, contentHash uint64, flowCount int) string {
	mac := hmac.New(sha256.New, key)
	// hash.Hash.Write never returns an error; the assignment satisfies errcheck.
	_, _ = fmt.Fprintf(mac, "%s\x00%d\x00%d", path, contentHash, flowCount)
	return hex.EncodeToString(mac.Sum(nil))
}

// TrustedForSuppression reports whether this cache entry may be trusted to
// suppress findings for the given path: its signature must verify under the
// local per-machine key. Unsigned entries and entries signed with a foreign
// key (e.g. shipped in a repo) return false.
func (c *FileTaintCache) TrustedForSuppression(path string) bool {
	if c == nil || c.Sig == "" {
		return false
	}
	want := signFileTaintCache(path, c.ContentHash, c.FlowCount)
	if want == "" {
		return false
	}
	return hmac.Equal([]byte(want), []byte(c.Sig))
}
