package graph

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates the per-machine cache HMAC key to a throwaway path for the
// whole graph test binary, so tests that write a FileTaintCache never create
// or read the real ~/.config/batou/cache_hmac.key.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "batou-cachekey-*")
	if err == nil {
		_ = os.Setenv("BATOU_CACHE_KEY_FILE", filepath.Join(dir, "cache_hmac.key"))
		defer func() { _ = os.RemoveAll(dir) }()
	}
	code := m.Run()
	os.Exit(code)
}

// TestFileTaintCache_TrustedRoundTrip: an entry written by SetFileTaintCache on
// this machine verifies under the local key.
func TestFileTaintCache_TrustedRoundTrip(t *testing.T) {
	cg := NewCallGraph(t.TempDir(), "s")
	cg.SetFileTaintCache("app/handler.go", 0xdeadbeef, 0)

	entry := cg.GetFileTaintCache("app/handler.go")
	if entry == nil {
		t.Fatal("expected cache entry")
	}
	if entry.Sig == "" {
		t.Fatal("expected a signature on a locally-written entry (is the key path writable?)")
	}
	if !entry.TrustedForSuppression("app/handler.go") {
		t.Error("locally-signed entry should be trusted for suppression")
	}
	// Path mismatch must not verify (signature binds the path).
	if entry.TrustedForSuppression("app/other.go") {
		t.Error("entry must not verify against a different path")
	}
}

// TestFileTaintCache_PoisonedUnsigned: a repo-shipped entry with no signature
// (the shape an attacker can trivially craft — FlowCount 0 + matching FNV hash)
// is NOT trusted, so it cannot suppress findings.
func TestFileTaintCache_PoisonedUnsigned(t *testing.T) {
	poisoned := &FileTaintCache{ContentHash: 0x1234, FlowCount: 0, Sig: ""}
	if poisoned.TrustedForSuppression("app/vuln.go") {
		t.Error("unsigned (poisoned) entry must never be trusted for suppression")
	}
}

// TestFileTaintCache_ForeignKey: an entry signed with a DIFFERENT key (an
// attacker's key, or a graph built on another machine) is not trusted here.
func TestFileTaintCache_ForeignKey(t *testing.T) {
	foreign := make([]byte, 32)
	if _, err := rand.Read(foreign); err != nil {
		t.Fatalf("rand: %v", err)
	}
	entry := &FileTaintCache{
		ContentHash: 0xabcd,
		FlowCount:   0,
		Sig:         signWithKey(foreign, "app/vuln.go", 0xabcd, 0),
	}
	if entry.TrustedForSuppression("app/vuln.go") {
		t.Error("entry signed with a foreign key must not be trusted")
	}
}

// TestFileTaintCache_Tampered: mutating FlowCount (or ContentHash) after signing
// invalidates the signature — an attacker can't take a genuine signed entry and
// flip it to FlowCount 0.
func TestFileTaintCache_Tampered(t *testing.T) {
	cg := NewCallGraph(t.TempDir(), "s")
	cg.SetFileTaintCache("app/handler.go", 0x55, 3) // 3 flows, signed
	entry := cg.GetFileTaintCache("app/handler.go")
	if entry == nil || entry.Sig == "" {
		t.Fatal("expected a signed entry")
	}
	entry.FlowCount = 0 // tamper: claim taint-clean
	if entry.TrustedForSuppression("app/handler.go") {
		t.Error("tampered FlowCount must invalidate the signature")
	}
}
