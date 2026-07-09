package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy trust boundary sanitizer tests (CWE-501)
// =========================================================================

func TestGroovy_TrustBoundary_Unsanitized(t *testing.T) {
	code := `
def handler(userInput) {
    session.setAttribute("userRole", userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for parameter -> session.setAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_TrustBoundary_Safe_ToInteger(t *testing.T) {
	code := `
def handler(userInput) {
    def safeId = userInput.toInteger()
    session.setAttribute("userId", safeId)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("toInteger() should sanitize trust boundary violation")
	}
}

func TestGroovy_TrustBoundary_Safe_ParseInt(t *testing.T) {
	code := `
def handler(userInput) {
    def safeId = Integer.parseInt(userInput)
    session.setAttribute("userId", safeId)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("Integer.parseInt() should sanitize trust boundary violation")
	}
}

func TestGroovy_TrustBoundary_Binding_Unsanitized(t *testing.T) {
	code := `
def handler(userInput) {
    binding.setVariable("userScript", userInput)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for parameter -> binding.setVariable")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_TrustBoundary_Safe_ToLong(t *testing.T) {
	code := `
def handler(userInput) {
    def safeVal = userInput.toLong()
    binding.setVariable("userId", safeVal)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("toLong() should sanitize trust boundary violation")
	}
}

// =========================================================================
// Groovy SSRF sanitizer tests (CWE-918)
// NOTE: getHost(), getScheme(), UrlValidator.isValid() are guard-style
// sanitizers — they validate a derived value but don't transform the tainted
// variable itself. These catalog entries work in the regex-based taint layer
// but not in tsflow's dataflow model. Only the unsanitized test is here.
// =========================================================================

func TestGroovy_SSRF_RestTemplate_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    def restTemplate = new RestTemplate()
    def result = restTemplate.getForObject(input, String.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for parameter -> restTemplate.getForObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SSRF_Safe_URLEncoderEncode(t *testing.T) {
	code := `
def handler(input) {
    def safe = URLEncoder.encode(input, "UTF-8")
    def restTemplate = new RestTemplate()
    def result = restTemplate.getForObject(safe, String.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("URLEncoder.encode() should sanitize SSRF flow")
	}
}

// =========================================================================
// Groovy LDAP sanitizer tests (CWE-90)
// NOTE: ESAPI chained calls (ESAPI.encoder().encodeForLDAP) are recognized
// in the regex taint layer but not by tsflow's call matcher. Only non-chained
// sanitizer tests are included here.
// =========================================================================

func TestGroovy_LDAP_Param_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    def ctx = new InitialDirContext(env)
    ctx.search("ou=users", "(uid=" + input + ")", null)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for parameter -> ctx.search")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_LDAP_Safe_LdapQueryBuilder(t *testing.T) {
	code := `
def handler(input) {
    def query = LdapQueryBuilder.query().base("ou=users").filter("uid", input)
    ldapTemplate.search(query)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapQueryBuilder.query() should sanitize LDAP injection")
	}
}

func TestGroovy_LDAP_Safe_NameEncode(t *testing.T) {
	code := `
def handler(input) {
    def safeDn = LdapEncoder.nameEncode(input)
    def ctx = new InitialDirContext(env)
    ctx.search("ou=users", "(uid=" + safeDn + ")", null)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapEncoder.nameEncode() should sanitize LDAP injection")
	}
}

func TestGroovy_LDAP_Safe_FilterEncode(t *testing.T) {
	code := `
def handler(input) {
    def safe = LdapEncoder.filterEncode(input)
    def ctx = new InitialDirContext(env)
    ctx.search("ou=users", "(uid=" + safe + ")", null)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("LdapEncoder.filterEncode() should sanitize LDAP injection (existing sanitizer)")
	}
}
