package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — CryptoSwift weak hash + legacy cipher tests (CWE-328 / CWE-327)
// =========================================================================
//
// CryptoSwift (github.com/krzyzanowskim/CryptoSwift) is a pure-Swift crypto
// library widely vendored by iOS apps. It exposes weak hashes (MD5, SHA1)
// and deprecated block ciphers (DES, Blowfish, RC4, RC2) through String /
// Array extensions, the static Digest API, and per-cipher constructors.
// These tests ensure a tainted source (req.query) flowing into any of those
// primitives produces a SnkCrypto flow.

func TestSwift_CryptoSwift_StringMD5_WeakHash(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) {
    let password = req.query["password"]
    let digest = password.md5()
    _ = digest
}
`
	flows := Analyze(code, "/app/Hasher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-hash flow for req.query -> String.md5()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CryptoSwift_DigestMD5_WeakHash(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) {
    let bytes = req.query["bytes"]
    let digest = Digest.md5(bytes)
    _ = digest
}
`
	flows := Analyze(code, "/app/Hasher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-hash flow for req.query -> Digest.md5(bytes)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CryptoSwift_StringSHA1_WeakHash(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) {
    let token = req.query["token"]
    let digest = token.sha1()
    _ = digest
}
`
	flows := Analyze(code, "/app/Hasher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-hash flow for req.query -> String.sha1()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CryptoSwift_DES_WeakCipher(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) throws {
    let key = req.query["key"]
    let cipher = try DES(key: key, blockMode: CBC(iv: Array(repeating: 0, count: 8)))
    _ = cipher
}
`
	flows := Analyze(code, "/app/Cipher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-cipher flow for req.query -> DES(key:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CryptoSwift_Blowfish_WeakCipher(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) throws {
    let key = req.query["key"]
    let cipher = try Blowfish(key: key, blockMode: CBC(iv: Array(repeating: 0, count: 8)))
    _ = cipher
}
`
	flows := Analyze(code, "/app/Cipher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-cipher flow for req.query -> Blowfish(key:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CryptoSwift_RC4_WeakCipher(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) throws {
    let key = req.query["key"]
    let cipher = try RC4(key: key)
    _ = cipher
}
`
	flows := Analyze(code, "/app/Cipher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-cipher flow for req.query -> RC4(key:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CryptoSwift_RC2_WeakCipher(t *testing.T) {
	code := `
import CryptoSwift
import Vapor

func handler(req: Request) throws {
    let key = req.query["key"]
    let cipher = try RC2(key: key)
    _ = cipher
}
`
	flows := Analyze(code, "/app/Cipher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-cipher flow for req.query -> RC2(key:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CommonCrypto_CC_MD2_WeakHash(t *testing.T) {
	code := `
import CommonCrypto
import Vapor

func handler(req: Request) {
    let data = req.query["data"]
    var digest = [UInt8](repeating: 0, count: Int(CC_MD2_DIGEST_LENGTH))
    CC_MD2(data, CC_LONG(data.count), &digest)
    _ = digest
}
`
	flows := Analyze(code, "/app/Hasher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-hash flow for req.query -> CC_MD2")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_CommonCrypto_CC_MD4_WeakHash(t *testing.T) {
	code := `
import CommonCrypto
import Vapor

func handler(req: Request) {
    let data = req.query["data"]
    var digest = [UInt8](repeating: 0, count: Int(CC_MD4_DIGEST_LENGTH))
    CC_MD4(data, CC_LONG(data.count), &digest)
    _ = digest
}
`
	flows := Analyze(code, "/app/Hasher.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected weak-hash flow for req.query -> CC_MD4")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: a non-CryptoSwift `.md5()` receiver with no taint reaching it
// should not produce a crypto flow for the CryptoSwift rule. This guards
// against the pattern being dragged in by any unrelated `.md5()` text.
func TestSwift_CryptoSwift_NoTaint_NoFlow(t *testing.T) {
	code := `
import CryptoSwift

func hashStatic() {
    let staticSalt = "app-constant-salt"
    let digest = staticSalt.md5()
    _ = digest
}
`
	flows := Analyze(code, "/app/Hasher.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto && f.Sink.ID == "swift.cryptoswift.md5" {
			t.Errorf("did not expect SnkCrypto flow for static-input .md5(); got flow from %s", f.Source.ID)
		}
	}
}
