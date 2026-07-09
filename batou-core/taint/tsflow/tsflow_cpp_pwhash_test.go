package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C++ modern password-hashing & constant-time-compare sanitizer tests
// (CWE-916 mitigation: memory-hard KDFs for credential storage;
//  CWE-208 mitigation: timing-safe credential comparison)
// =========================================================================

func TestCPP_LibsodiumCryptoPwhashStr_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <cstdlib>
#include <cstring>

void hashPasswordForStorage() {
    char *password = getenv("PASSWORD");
    char hashed[crypto_pwhash_STRBYTES];
    crypto_pwhash_str(hashed, password, strlen(password),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE);
}
`
	flows := Analyze(code, "/app/pwhash_str.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypto_pwhash_str() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LibsodiumCryptoPwhashStrVerify_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <cstdlib>
#include <cstring>

int verifyPassword(const char *stored_hash) {
    char *password = getenv("PASSWORD");
    return crypto_pwhash_str_verify(stored_hash, password, strlen(password));
}
`
	flows := Analyze(code, "/app/pwhash_verify.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypto_pwhash_str_verify() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LibsodiumCryptoPwhash_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <cstdlib>
#include <cstring>

void deriveKey(unsigned char *salt) {
    char *password = getenv("PASSWORD");
    unsigned char key[32];
    crypto_pwhash(key, sizeof(key), password, strlen(password), salt,
                  crypto_pwhash_OPSLIMIT_MODERATE,
                  crypto_pwhash_MEMLIMIT_MODERATE,
                  crypto_pwhash_ALG_ARGON2ID13);
}
`
	flows := Analyze(code, "/app/pwhash_kdf.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("crypto_pwhash() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_LibsodiumSodiumMemcmp_Sanitizes(t *testing.T) {
	code := `
#include <sodium.h>
#include <cstdlib>
#include <cstring>

int compareTokens(const unsigned char *expected) {
    char *user_token = getenv("USER_TOKEN");
    return sodium_memcmp(user_token, expected, 32);
}
`
	flows := Analyze(code, "/app/memcmp.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("sodium_memcmp() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Argon2idHashEncoded_Sanitizes(t *testing.T) {
	code := `
#include <argon2.h>
#include <cstdlib>
#include <cstring>

void hashWithArgon2id(const uint8_t *salt, size_t saltlen) {
    char *password = getenv("PASSWORD");
    char encoded[256];
    argon2id_hash_encoded(3, 65536, 4, password, strlen(password),
                          salt, saltlen, 32, encoded, sizeof(encoded));
}
`
	flows := Analyze(code, "/app/argon2id_encoded.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("argon2id_hash_encoded() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Argon2idHashRaw_Sanitizes(t *testing.T) {
	code := `
#include <argon2.h>
#include <cstdlib>
#include <cstring>

void deriveKeyArgon2id(const uint8_t *salt, size_t saltlen) {
    char *password = getenv("PASSWORD");
    uint8_t key[32];
    argon2id_hash_raw(3, 65536, 4, password, strlen(password),
                      salt, saltlen, key, sizeof(key));
}
`
	flows := Analyze(code, "/app/argon2id_raw.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("argon2id_hash_raw() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Argon2Verify_Sanitizes(t *testing.T) {
	code := `
#include <argon2.h>
#include <cstdlib>
#include <cstring>

int verifyArgon2(const char *encoded_hash) {
    char *password = getenv("PASSWORD");
    return argon2_verify(encoded_hash, password, strlen(password), Argon2_id);
}
`
	flows := Analyze(code, "/app/argon2_verify.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("argon2_verify() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_BotanArgon2_Sanitizes(t *testing.T) {
	code := `
#include <botan/argon2.h>
#include <botan/auto_rng.h>
#include <cstdlib>
#include <string>

std::string hashWithBotan() {
    std::string password = std::getenv("PASSWORD");
    Botan::AutoSeeded_RNG rng;
    auto hasher = Botan::Argon2(Botan::Argon2::Variant::Argon2id, 65536, 3, 4);
    return hasher.derive_key(32, password.data(), password.size(), nullptr, 0);
}
`
	flows := Analyze(code, "/app/botan_argon2.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Botan::Argon2 should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_BotanBcrypt_Sanitizes(t *testing.T) {
	code := `
#include <botan/bcrypt.h>
#include <botan/auto_rng.h>
#include <cstdlib>
#include <string>

std::string hashBcrypt() {
    std::string password = std::getenv("PASSWORD");
    Botan::AutoSeeded_RNG rng;
    return Botan::generate_bcrypt(password, rng, 12);
}

bool checkBcrypt(const std::string &stored) {
    std::string password = std::getenv("PASSWORD");
    return Botan::check_bcrypt(password, stored);
}
`
	flows := Analyze(code, "/app/botan_bcrypt.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Botan::generate_bcrypt/check_bcrypt should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_OpensslCryptoMemcmp_Sanitizes(t *testing.T) {
	code := `
#include <openssl/crypto.h>
#include <cstdlib>
#include <cstring>

int verifyMac(const unsigned char *expected) {
    char *user_mac = getenv("USER_MAC");
    return CRYPTO_memcmp(user_mac, expected, 32);
}
`
	flows := Analyze(code, "/app/crypto_memcmp.cpp", rules.LangCPP)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("CRYPTO_memcmp() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: verify that calling these password-hashing sanitizers on
// non-credential code does not introduce false-positive sanitization (i.e.
// they only neutralize SnkCrypto, not unrelated sink categories).
func TestCPP_PwhashSanitizers_DoNotMaskFileWrite(t *testing.T) {
	code := `
#include <sodium.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

void writeUserFile() {
    char *userPath = getenv("FILE_PATH");
    char hash[crypto_pwhash_STRBYTES];
    crypto_pwhash_str(hash, userPath, strlen(userPath),
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE);
    FILE *f = fopen(userPath, "w");
    fputs("data", f);
}
`
	flows := Analyze(code, "/app/pwhash_unrelated.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow — pwhash sanitizers must not neutralize SnkFileWrite on a separate variable use")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
