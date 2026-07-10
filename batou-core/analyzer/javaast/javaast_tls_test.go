package javaast

import "testing"

// =========================================================================
// COVERAGE ADD (cov/java) — CWE-295 improper TLS certificate / hostname
// validation. Structural detection: only fires on a provably permissive
// verifier / trust-manager body. A verifier/trust-manager with real logic in
// its body must stay clean (the precision guarantee).
// =========================================================================

// --- BATOU-JAVAAST-010: accept-all HostnameVerifier ---

func TestInsecureTLS_HostnameVerifierLambdaTrue(t *testing.T) {
	code := `
import javax.net.ssl.HttpsURLConnection;
public class C {
    void f(HttpsURLConnection conn) {
        conn.setHostnameVerifier((hostname, session) -> true);
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-010") == nil {
		t.Error("expected BATOU-JAVAAST-010 for accept-all HostnameVerifier lambda")
	}
}

func TestInsecureTLS_HostnameVerifierAnonClassTrue(t *testing.T) {
	code := `
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
public class C {
    void f() {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        });
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-010") == nil {
		t.Error("expected BATOU-JAVAAST-010 for accept-all anonymous HostnameVerifier")
	}
}

func TestInsecureTLS_OkHttpHostnameVerifierTrue(t *testing.T) {
	code := `
public class C {
    void f(okhttp3.OkHttpClient.Builder builder) {
        builder.hostnameVerifier((hostname, session) -> true);
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-010") == nil {
		t.Error("expected BATOU-JAVAAST-010 for OkHttp accept-all hostnameVerifier")
	}
}

// A verifier with real comparison logic must NOT fire.
func TestInsecureTLS_HostnameVerifierWithLogicSafe(t *testing.T) {
	code := `
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;
public class C {
    void f(HttpsURLConnection conn) {
        conn.setHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return hostname.equals("api.example.com");
            }
        });
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-010") != nil {
		t.Error("did not expect BATOU-JAVAAST-010 for a verifier with real hostname comparison")
	}
}

// A lambda that conditionally returns must NOT fire (body is not a bare true).
func TestInsecureTLS_HostnameVerifierConditionalSafe(t *testing.T) {
	code := `
import javax.net.ssl.HttpsURLConnection;
public class C {
    void f(HttpsURLConnection conn) {
        conn.setHostnameVerifier((hostname, session) -> hostname.startsWith("internal."));
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-010") != nil {
		t.Error("did not expect BATOU-JAVAAST-010 for a conditional verifier lambda")
	}
}

// --- BATOU-JAVAAST-011: all-trusting X509TrustManager ---

func TestInsecureTLS_EmptyTrustManager(t *testing.T) {
	code := `
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
public class C {
    void f(SSLContext sslctx) throws Exception {
        sslctx.init(null, new TrustManager[]{ new X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return null; }
        }}, null);
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-011") == nil {
		t.Error("expected BATOU-JAVAAST-011 for empty-bodied X509TrustManager")
	}
}

// A trust manager that actually validates (non-empty check bodies) must NOT fire.
func TestInsecureTLS_ValidatingTrustManagerSafe(t *testing.T) {
	code := `
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
public class C {
    void f(SSLContext sslctx) throws Exception {
        sslctx.init(null, new TrustManager[]{ new X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                if (chain == null || chain.length == 0) { throw new CertificateException("empty chain"); }
                chain[0].checkValidity();
            }
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                chain[0].checkValidity();
            }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }}, null);
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-011") != nil {
		t.Error("did not expect BATOU-JAVAAST-011 for a validating X509TrustManager")
	}
}

// The default TrustManagerFactory path (no custom trust manager) must NOT fire.
func TestInsecureTLS_DefaultTrustManagerSafe(t *testing.T) {
	code := `
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
public class C {
    void f(SSLContext sslctx, TrustManagerFactory tmf) throws Exception {
        sslctx.init(null, tmf.getTrustManagers(), null);
    }
}
`
	findings := scanJava(code)
	if findByRule(findings, "BATOU-JAVAAST-011") != nil {
		t.Error("did not expect BATOU-JAVAAST-011 for the default TrustManagerFactory path")
	}
}
