package misconfig

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// --- BATOU-MISC-012: C/C++ TLS verification disabled (CWE-295) ---

func TestMISC012_CurlVerifyPeerOff(t *testing.T) {
	content := `#include <curl/curl.h>
void f(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
}`
	result := testutil.ScanContent(t, "/app/net.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_CurlVerifyPeerFalse(t *testing.T) {
	content := `void f(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, false);
}`
	result := testutil.ScanContent(t, "/app/net.c", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_CurlVerifyHostOff(t *testing.T) {
	content := `void f(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);
}`
	result := testutil.ScanContent(t, "/app/net.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

// Value 1 is also insecure (legacy quirk) — must fire.
func TestMISC012_CurlVerifyHostOne(t *testing.T) {
	content := `void f(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 1L);
}`
	result := testutil.ScanContent(t, "/app/net.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_OpenSSLVerifyNone(t *testing.T) {
	content := `void setup(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}`
	result := testutil.ScanContent(t, "/app/tls.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_BoostVerifyNone(t *testing.T) {
	content := `void f(boost::asio::ssl::context &ctx) {
    ctx.set_verify_mode(boost::asio::ssl::verify_none);
}`
	result := testutil.ScanContent(t, "/app/asio.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_QtVerifyNone(t *testing.T) {
	content := `void f(QSslSocket *s) {
    s->setPeerVerifyMode(QSslSocket::VerifyNone);
}`
	result := testutil.ScanContent(t, "/app/qt.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_QtIgnoreSslErrors(t *testing.T) {
	content := `void f(QNetworkReply *reply) {
    reply->ignoreSslErrors();
}`
	result := testutil.ScanContent(t, "/app/qt.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

func TestMISC012_GrpcInsecureChannel(t *testing.T) {
	content := `void f() {
    auto ch = grpc::CreateChannel(addr, grpc::InsecureChannelCredentials());
}`
	result := testutil.ScanContent(t, "/app/rpc.cpp", content)
	testutil.MustFindRule(t, result, "BATOU-MISC-012")
}

// --- Safe / near-miss cases that must NOT fire ---

// CURLOPT_SSL_VERIFYPEER set to 1 (the secure value) — must NOT fire.
func TestMISC012_Safe_CurlVerifyPeerOn(t *testing.T) {
	content := `void f(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
}`
	result := testutil.ScanContent(t, "/app/net.cpp", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-012")
}

// CURLOPT_SSL_VERIFYHOST set to 2 (the only secure value) — must NOT fire.
func TestMISC012_Safe_CurlVerifyHostTwo(t *testing.T) {
	content := `void f(CURL *h) {
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
}`
	result := testutil.ScanContent(t, "/app/net.cpp", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-012")
}

// OpenSSL SSL_VERIFY_PEER (the secure flag) — must NOT fire.
func TestMISC012_Safe_OpenSSLVerifyPeer(t *testing.T) {
	content := `void setup(SSL_CTX *ctx) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_cb);
}`
	result := testutil.ScanContent(t, "/app/tls.cpp", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-012")
}

// Boost.Asio verify_peer (secure) — must NOT fire.
func TestMISC012_Safe_BoostVerifyPeer(t *testing.T) {
	content := `void f(boost::asio::ssl::context &ctx) {
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
}`
	result := testutil.ScanContent(t, "/app/asio.cpp", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-012")
}

// Qt selective ignoreSslErrors(list) — legitimate, must NOT fire.
func TestMISC012_Safe_QtIgnoreSslErrorsSelective(t *testing.T) {
	content := `void f(QNetworkReply *reply, QList<QSslError> expected) {
    reply->ignoreSslErrors(expected);
}`
	result := testutil.ScanContent(t, "/app/qt.cpp", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-012")
}

// Commented-out disable — must NOT fire.
func TestMISC012_Safe_Commented(t *testing.T) {
	content := `void f(CURL *h) {
    // curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
}`
	result := testutil.ScanContent(t, "/app/net.cpp", content)
	testutil.MustNotFindRule(t, result, "BATOU-MISC-012")
}
