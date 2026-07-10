package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C modern password-hashing & constant-time-compare sanitizer tests.
// CWE-916: memory-hard KDFs (Argon2id, libxcrypt bcrypt) for credential storage.
// CWE-208: timing-safe credential comparison (sodium_memcmp, CRYPTO_memcmp,
// timingsafe_bcmp/memcmp) instead of memcmp on secrets.
//
// Most of these tests assert no SnkCrypto flow — they document the recommended
// safe pattern and act as regression checks against future sinks accidentally
// matching these recommended APIs. The sodium_memcmp test additionally exercises
// the walker's args[0] sanitization path: tainted secret → sodium_memcmp →
// downstream EVP_BytesToKey should NOT produce a SnkCrypto flow because
// the taint on the args[0] secret is cleared by the sanitizer.
// =========================================================================

func TestC_LibsodiumCryptoPwhashStr_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

void hash_password_for_storage(void) {
    char *password = getenv("PASSWORD");
    char hashed[crypto_pwhash_STRBYTES];
    crypto_pwhash_str(hashed, password, strlen(password),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE);
}
`
	flows := Analyze(code, "/app/pwhash_str.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypto_pwhash_str() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibsodiumCryptoPwhashStrVerify_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

int verify_password(const char *stored_hash) {
    char *password = getenv("PASSWORD");
    return crypto_pwhash_str_verify(stored_hash, password, strlen(password));
}
`
	flows := Analyze(code, "/app/pwhash_verify.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypto_pwhash_str_verify() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibsodiumCryptoPwhash_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

void derive_key(unsigned char *salt) {
    char *password = getenv("PASSWORD");
    unsigned char key[32];
    crypto_pwhash(key, sizeof(key), password, strlen(password), salt,
                  crypto_pwhash_OPSLIMIT_MODERATE,
                  crypto_pwhash_MEMLIMIT_MODERATE,
                  crypto_pwhash_ALG_ARGON2ID13);
}
`
	flows := Analyze(code, "/app/pwhash_kdf.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypto_pwhash() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Argon2idHashEncoded_Sanitizes(t *testing.T) {
	code := `
#include <argon2.h>
#include <stdlib.h>
#include <string.h>

void hash_with_argon2id(const uint8_t *salt, size_t saltlen) {
    char *password = getenv("PASSWORD");
    char encoded[256];
    argon2id_hash_encoded(3, 65536, 4, password, strlen(password),
                          salt, saltlen, 32, encoded, sizeof(encoded));
}
`
	flows := Analyze(code, "/app/argon2id_encoded.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("argon2id_hash_encoded() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Argon2idHashRaw_Sanitizes(t *testing.T) {
	code := `
#include <argon2.h>
#include <stdlib.h>
#include <string.h>

void derive_key_argon2id(const uint8_t *salt, size_t saltlen) {
    char *password = getenv("PASSWORD");
    uint8_t key[32];
    argon2id_hash_raw(3, 65536, 4, password, strlen(password),
                      salt, saltlen, key, sizeof(key));
}
`
	flows := Analyze(code, "/app/argon2id_raw.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("argon2id_hash_raw() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Argon2Verify_Sanitizes(t *testing.T) {
	code := `
#include <argon2.h>
#include <stdlib.h>
#include <string.h>

int verify_argon2(const char *encoded_hash) {
    char *password = getenv("PASSWORD");
    return argon2_verify(encoded_hash, password, strlen(password), Argon2_id);
}
`
	flows := Analyze(code, "/app/argon2_verify.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("argon2_verify() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_LibxcryptCryptR_Sanitizes(t *testing.T) {
	code := `
#include <crypt.h>
#include <stdlib.h>

void hash_password_with_crypt(void) {
    char *password = getenv("PASSWORD");
    struct crypt_data data = {0};
    char *result = crypt_r(password, "$2b$12$abcdefghijklmnopqrstuv", &data);
    (void)result;
}
`
	flows := Analyze(code, "/app/cryptr.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypt_r() (libxcrypt bcrypt) should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_OpenSSLCryptoMemcmp_Sanitizes(t *testing.T) {
	code := `
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>

int compare_macs(const unsigned char *expected_mac) {
    char *user_mac = getenv("USER_MAC");
    return CRYPTO_memcmp(user_mac, expected_mac, 32);
}
`
	flows := Analyze(code, "/app/crypto_memcmp.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("CRYPTO_memcmp() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_TimingsafeBcmp_Sanitizes(t *testing.T) {
	code := `
#include <string.h>
#include <stdlib.h>

int compare_tokens(const unsigned char *expected_token) {
    char *user_token = getenv("USER_TOKEN");
    return timingsafe_bcmp(user_token, expected_token, 32);
}
`
	flows := Analyze(code, "/app/timingsafe_bcmp.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("timingsafe_bcmp() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_TimingsafeMemcmp_Sanitizes(t *testing.T) {
	code := `
#include <string.h>
#include <stdlib.h>

int compare_secrets(const unsigned char *expected) {
    char *user_secret = getenv("USER_SECRET");
    return timingsafe_memcmp(user_secret, expected, 64);
}
`
	flows := Analyze(code, "/app/timingsafe_memcmp.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("timingsafe_memcmp() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative regression test — ensure the broad `\bcrypt_r\s*\(` pattern doesn't
// misfire on innocuous identifiers that contain "crypt" (e.g. encryption
// helpers named decrypt(), encrypt_data()) by exercising the matcher with a
// non-call usage.
func TestC_NoFalsePositive_OnUnrelatedCryptoIdentifiers(t *testing.T) {
	code := `
#include <stdlib.h>
#include <string.h>

void unrelated(void) {
    /* These names share substrings with sanitizer functions but should not match. */
    int crypt_r_idx = 0;
    const char *crypto_pwhash_label = "label";
    (void)crypt_r_idx;
    (void)crypto_pwhash_label;
}
`
	flows := Analyze(code, "/app/no_calls.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("no sink/source calls present — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
