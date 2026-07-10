package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Perl — weak-crypto sinks (CWE-327, CWE-328)
//
// Covers weak hash algorithms (MD2, MD4) and legacy block ciphers
// (Blowfish, IDEA, RC2, CAST5) that sit alongside the existing DES/RC4/ECB
// entries.
//
// Flow shape: user input -> weak crypto primitive. For hashes we taint the
// input being hashed (DangerousArgs=[0]); for block ciphers we taint the
// key passed to ->new() since a tainted key is what tsflow uses to trip
// the usage-based sink (DangerousArgs=[-1]).
//
// Kept in a dedicated file to avoid the tsflow_test.go merge bottleneck.
// =========================================================================

// Digest::MD2 — collision-broken hash via functional API.
func TestPerl_Crypto_DigestMD2_Func(t *testing.T) {
	code := `
use CGI;
use Digest::MD2 qw(md2_hex);
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("data");
    return md2_hex($input);
}
`
	flows := Analyze(code, "/app/hash.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> md2_hex()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Digest::MD2 — bare md2() also exported by the module.
func TestPerl_Crypto_DigestMD2_Bare(t *testing.T) {
	code := `
use CGI;
use Digest::MD2 qw(md2);
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("data");
    return md2($input);
}
`
	flows := Analyze(code, "/app/hash.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> md2()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Digest::MD4 — still surfaces in NTLM/SMB legacy code paths.
func TestPerl_Crypto_DigestMD4_Func(t *testing.T) {
	code := `
use CGI;
use Digest::MD4 qw(md4_hex);
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("password");
    return md4_hex($input);
}
`
	flows := Analyze(code, "/app/hash.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> md4_hex()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Digest::MD2 — object API (Digest::MD2->new).
func TestPerl_Crypto_DigestMD2_Class(t *testing.T) {
	code := `
use CGI;
use Digest::MD2;
sub handler {
    my $cgi = CGI->new;
    my $input = $cgi->param("data");
    my $ctx = Digest::MD2->new($input);
    return $ctx->hexdigest;
}
`
	flows := Analyze(code, "/app/hash.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> Digest::MD2->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Crypt::Blowfish — 64-bit block cipher, SWEET32-vulnerable.
func TestPerl_Crypto_CryptBlowfish(t *testing.T) {
	code := `
use CGI;
use Crypt::Blowfish;
sub handler {
    my $cgi = CGI->new;
    my $key = $cgi->param("key");
    my $cipher = Crypt::Blowfish->new($key);
    return $cipher->encrypt("block___");
}
`
	flows := Analyze(code, "/app/enc.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> Crypt::Blowfish->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Crypt::Blowfish_PP — pure-perl variant of Blowfish, same weakness.
func TestPerl_Crypto_CryptBlowfishPP(t *testing.T) {
	code := `
use CGI;
use Crypt::Blowfish_PP;
sub handler {
    my $cgi = CGI->new;
    my $key = $cgi->param("key");
    my $cipher = Crypt::Blowfish_PP->new($key);
    return $cipher->encrypt("block___");
}
`
	flows := Analyze(code, "/app/enc.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> Crypt::Blowfish_PP->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Crypt::IDEA — 64-bit block cipher, dropped from TLS 1.3.
func TestPerl_Crypto_CryptIDEA(t *testing.T) {
	code := `
use CGI;
use Crypt::IDEA;
sub handler {
    my $cgi = CGI->new;
    my $key = $cgi->param("key");
    my $cipher = Crypt::IDEA->new($key);
    return $cipher->encrypt("block___");
}
`
	flows := Analyze(code, "/app/enc.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> Crypt::IDEA->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Crypt::RC2 — obsolete cipher per RFC 2268.
func TestPerl_Crypto_CryptRC2(t *testing.T) {
	code := `
use CGI;
use Crypt::RC2;
sub handler {
    my $cgi = CGI->new;
    my $key = $cgi->param("key");
    my $cipher = Crypt::RC2->new($key);
    return $cipher->encrypt("block___");
}
`
	flows := Analyze(code, "/app/enc.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> Crypt::RC2->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Crypt::CAST5 — CAST-128, 64-bit block, deprecated.
func TestPerl_Crypto_CryptCAST5(t *testing.T) {
	code := `
use CGI;
use Crypt::CAST5;
sub handler {
    my $cgi = CGI->new;
    my $key = $cgi->param("key");
    my $cipher = Crypt::CAST5->new($key);
    return $cipher->encrypt("block___");
}
`
	flows := Analyze(code, "/app/enc.pl", rules.LangPerl)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for CGI param -> Crypt::CAST5->new")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe baseline — Crypt::Cipher::AES (strong cipher) should NOT fire the
// weak-crypto sinks we just added.
func TestPerl_Crypto_AES_Safe(t *testing.T) {
	code := `
use CGI;
use Crypt::Cipher::AES;
sub handler {
    my $cgi = CGI->new;
    my $key = $cgi->param("key");
    my $cipher = Crypt::Cipher::AES->new($key);
    return $cipher->encrypt("block___16bytes_");
}
`
	flows := Analyze(code, "/app/enc.pl", rules.LangPerl)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Errorf("unexpected SnkCrypto flow for Crypt::Cipher::AES: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
