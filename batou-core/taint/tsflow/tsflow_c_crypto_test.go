package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C weak crypto sink tests — tainted data flowing into weak crypto functions
// =========================================================================

// EVP_BytesToKey: tainted password used with weak single-iteration KDF
func TestC_EVP_BytesToKey_WeakKDF(t *testing.T) {
	code := `
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

void derive_key(void) {
    char *password = getenv("PASSWORD");
    unsigned char key[32], iv[16];
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(), NULL,
                   (unsigned char *)password, strlen(password), 1, key, iv);
}
`
	flows := Analyze(code, "/app/kdf.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for getenv -> EVP_BytesToKey() weak KDF")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// srandom: tainted seed makes PRNG output predictable
func TestC_Srandom_WeakPRNG(t *testing.T) {
	code := `
#include <stdlib.h>

void seed_rng(void) {
    char *seed_str = getenv("SEED");
    unsigned int seed = atoi(seed_str);
    srandom(seed);
}
`
	flows := Analyze(code, "/app/rng.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for getenv -> srandom() weak PRNG seeding")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// srand48: tainted seed makes drand48/lrand48 output predictable
func TestC_Srand48_WeakPRNG(t *testing.T) {
	code := `
#include <stdlib.h>

void seed_rng48(void) {
    char *seed_str = getenv("SEED");
    long seed = atol(seed_str);
    srand48(seed);
}
`
	flows := Analyze(code, "/app/rng48.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for getenv -> srand48() weak PRNG seeding")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// EVP_md5 via DigestUpdate: tainted data hashed with weak MD5 through EVP API
func TestC_EVP_MD5_ViaDigestUpdate(t *testing.T) {
	code := `
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

void hash_input(void) {
    char *data = getenv("USER_INPUT");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, data, strlen(data));
}
`
	flows := Analyze(code, "/app/hash.c", rules.LangC)
	// EVP_md5() is a config call (no tainted args) — detected by regex layer.
	// The tainted data flows through EVP_DigestUpdate, which is not a registered sink.
	// This test documents the expected behavior: no tsflow finding for EVP cipher constants.
	t.Logf("EVP_md5 via DigestUpdate: got %d flows", len(flows))
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}

// Direct MD5(): tainted data hashed with weak MD5 (existing sink, validates flow)
func TestC_MD5_Direct_WeakHash(t *testing.T) {
	code := `
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>

void hash_env(void) {
    char *input = getenv("SECRET");
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)input, strlen(input), digest);
}
`
	flows := Analyze(code, "/app/hash.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected crypto flow for getenv -> MD5() weak hash")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C crypto sanitizer tests — safe patterns that neutralize crypto taint
// =========================================================================

func TestC_Getrandom_Sanitizes(t *testing.T) {
	code := `
#include <sys/random.h>

void generate_secure_token(void) {
    unsigned char buf[32];
    getrandom(buf, sizeof(buf), 0);
}
`
	flows := Analyze(code, "/app/token_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("getrandom() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Getentropy_Sanitizes(t *testing.T) {
	code := `
#include <unistd.h>

void generate_entropy(void) {
    unsigned char buf[32];
    getentropy(buf, sizeof(buf));
}
`
	flows := Analyze(code, "/app/entropy_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("getentropy() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_PBKDF2_Sanitizes(t *testing.T) {
	code := `
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

void derive_key_safe(void) {
    char *password = getenv("PASSWORD");
    unsigned char key[32], salt[16];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                       100000, EVP_sha256(), sizeof(key), key);
}
`
	flows := Analyze(code, "/app/kdf_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("PKCS5_PBKDF2_HMAC() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_ChaCha20Poly1305_SafeCipher(t *testing.T) {
	code := `
#include <openssl/evp.h>

void encrypt_safe(void) {
    unsigned char key[32], nonce[12];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);
}
`
	flows := Analyze(code, "/app/crypto_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("EVP_chacha20_poly1305() should neutralize crypto taint — no SnkCrypto flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
