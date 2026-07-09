package misconfig

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// C/C++ TLS / certificate-verification misconfiguration (CWE-295).
//
// These are *config-constant* flaws, not taint flows: the insecure value is
// the vulnerability, so they are implemented as regex rules rather than taint
// sinks. Every pattern is anchored on a library-unique option/enum/function
// token PLUS the specific insecure value argument, so the rule fires ONLY on
// an actual disable — never on the safe form (e.g. `...VERIFYPEER, 1`).
//
// Detections (all CWE-295, A02:2021 / A07:2021):
//   - libcurl   CURLOPT_SSL_VERIFYPEER set to 0/false
//   - libcurl   CURLOPT_SSL_VERIFYHOST set to 0/1/false (only 2 is safe)
//   - OpenSSL   SSL_CTX_set_verify / SSL_set_verify with SSL_VERIFY_NONE
//   - Boost.Asio .set_verify_mode(ssl::verify_none)
//   - Qt        setPeerVerifyMode(QSslSocket::VerifyNone|QueryPeer)
//   - Qt        ->ignoreSslErrors()   (blanket no-arg overload)
//   - gRPC      grpc::Insecure{Channel,Server}Credentials()
//
// Implemented independently from the CWE-295 definition and each framework's
// public API documentation.
// ---------------------------------------------------------------------------

var (
	// libcurl: peer-cert verification disabled. CURLOPT_SSL_VERIFYPEER is a
	// libcurl-unique macro; the safe value is exactly 1, so matching 0/0L/false
	// is an unambiguous disable. We require the option and value in the same
	// setopt-shaped call.
	reCurlVerifyPeerOff = regexp.MustCompile(`CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0L?|false|FALSE)\b`)

	// libcurl: hostname verification disabled. Only the value 2 enables the
	// hostname check; 0 disables it and 1 is a legacy quirk that ALSO disables
	// it. Matching 0/1/false catches both insecure forms (the 1 case is the
	// subtle one many scanners miss).
	reCurlVerifyHostOff = regexp.MustCompile(`CURLOPT_SSL_VERIFYHOST\s*,\s*(?:0L?|1L?|false|FALSE)\b`)

	// OpenSSL: peer verification turned off. Requires BOTH the OpenSSL-unique
	// function name (SSL_set_verify / SSL_CTX_set_verify) AND the
	// SSL_VERIFY_NONE flag in the same call. SSL_VERIFY_PEER is untouched.
	reOpenSSLVerifyNone = regexp.MustCompile(`SSL_(?:CTX_)?set_verify\s*\(\s*[^,]+,\s*SSL_VERIFY_NONE\b`)

	// Boost.Asio: verify mode set to verify_none. The ssl::verify_none enum is
	// Boost.Asio-specific and appears only in verify-mode configuration.
	reBoostVerifyNone = regexp.MustCompile(`\.set_verify_mode\s*\(\s*(?:boost::asio::)?ssl::verify_none\b`)

	// Qt: peer verify mode set to VerifyNone / QueryPeer (both insecure for a
	// TLS client; only VerifyPeer is safe). QSslSocket::VerifyNone is a
	// Qt-unique enum.
	reQtVerifyNone = regexp.MustCompile(`setPeerVerifyMode\s*\(\s*QSslSocket::(?:VerifyNone|QueryPeer)\b`)

	// Qt: blanket SSL-error suppression. The no-argument ignoreSslErrors()
	// overload ignores ALL errors; the QList<QSslError> overload selectively
	// allows specific expected errors and is legitimate. Gate on empty parens.
	reQtIgnoreSslErrors = regexp.MustCompile(`->\s*ignoreSslErrors\s*\(\s*\)`)

	// gRPC: plaintext channel/server credentials (no TLS). The
	// grpc::Insecure*Credentials factory names are gRPC-unique.
	reGrpcInsecureCreds = regexp.MustCompile(`grpc::Insecure(?:Channel|Server)Credentials\s*\(`)
)

func init() {
	rules.Register(&CppTLSVerificationDisabled{})
}

// ---------------------------------------------------------------------------
// BATOU-MISC-012: C/C++ TLS certificate verification disabled (CWE-295)
// ---------------------------------------------------------------------------

type CppTLSVerificationDisabled struct{}

func (r *CppTLSVerificationDisabled) ID() string   { return "BATOU-MISC-012" }
func (r *CppTLSVerificationDisabled) Name() string { return "CppTLSVerificationDisabled" }
func (r *CppTLSVerificationDisabled) DefaultSeverity() rules.Severity {
	return rules.High
}
func (r *CppTLSVerificationDisabled) Description() string {
	return "Detects disabled TLS certificate/peer/hostname verification in C/C++ network clients (libcurl, OpenSSL, Boost.Asio, Qt, gRPC), which exposes connections to man-in-the-middle attacks."
}
func (r *CppTLSVerificationDisabled) Languages() []rules.Language {
	return []rules.Language{rules.LangC, rules.LangCPP}
}

// tlsPattern pairs a compiled regex with the precise diagnostic to emit.
type tlsPattern struct {
	re         *regexp.Regexp
	title      string
	suggestion string
	cwe        string
}

func (r *CppTLSVerificationDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	patterns := []tlsPattern{
		{
			re:         reCurlVerifyPeerOff,
			title:      "TLS peer verification disabled (libcurl CURLOPT_SSL_VERIFYPEER = 0)",
			suggestion: "Remove the override or set CURLOPT_SSL_VERIFYPEER to 1L. Only disable it against a known test server, never in production.",
			cwe:        "CWE-295",
		},
		{
			re:         reCurlVerifyHostOff,
			title:      "TLS hostname verification disabled (libcurl CURLOPT_SSL_VERIFYHOST != 2)",
			suggestion: "Set CURLOPT_SSL_VERIFYHOST to 2L. The values 0 and 1 both skip the hostname check, allowing MITM with any valid-but-wrong-host certificate.",
			cwe:        "CWE-295",
		},
		{
			re:         reOpenSSLVerifyNone,
			title:      "TLS peer verification disabled (OpenSSL SSL_VERIFY_NONE on a client)",
			suggestion: "Use SSL_VERIFY_PEER (with SSL_VERIFY_FAIL_IF_NO_PEER_CERT for servers) and supply a real verify callback or trust store. SSL_VERIFY_NONE on a TLS client accepts any certificate.",
			cwe:        "CWE-295",
		},
		{
			re:         reBoostVerifyNone,
			title:      "TLS peer verification disabled (Boost.Asio ssl::verify_none)",
			suggestion: "Call set_verify_mode(ssl::verify_peer) and load a trust store with set_default_verify_paths()/load_verify_file(). verify_none accepts any certificate.",
			cwe:        "CWE-295",
		},
		{
			re:         reQtVerifyNone,
			title:      "TLS peer verification disabled (Qt QSslSocket::VerifyNone)",
			suggestion: "Use QSslSocket::VerifyPeer. VerifyNone (and QueryPeer on a client) does not validate the server certificate.",
			cwe:        "CWE-295",
		},
		{
			re:         reQtIgnoreSslErrors,
			title:      "TLS errors blanket-ignored (Qt ignoreSslErrors() with no arguments)",
			suggestion: "Pass the specific expected QSslError list to ignoreSslErrors(const QList<QSslError>&) instead of calling the no-argument overload, which suppresses ALL certificate errors.",
			cwe:        "CWE-295",
		},
		{
			re:         reGrpcInsecureCreds,
			title:      "gRPC channel/server using insecure (plaintext) credentials",
			suggestion: "Use grpc::SslCredentials / grpc::SslServerCredentials with a real certificate. InsecureChannelCredentials() sends all RPC traffic unencrypted.",
			cwe:        "CWE-295",
		},
	}

	for i, line := range lines {
		if isCppCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := rules.GFindIndexLower(p.re, line, lowered[i]); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         p.title,
					Description:   "Disabling TLS certificate, peer, or hostname verification removes the protection against man-in-the-middle attacks: an attacker can present any certificate (or none) and the client will trust it.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncateTLS(line[loc[0]:loc[1]], 120),
					Suggestion:    p.suggestion,
					CWEID:         p.cwe,
					OWASPCategory: "A07:2021-Identification and Authentication Failures",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"misconfig", "tls", "cert-validation", "c-cpp"},
				})
				break
			}
		}
	}

	return findings
}

// truncateTLS keeps matched text within maxLen characters.
func truncateTLS(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// isCppCommentLine reports whether a C/C++ source line is a comment-only line.
func isCppCommentLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*")
}
