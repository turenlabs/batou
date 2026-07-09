package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Ruby — JWT signature-verification bypass (CWE-347)
// =========================================================================

// jose-ruby JOSE::JWT.peek_payload returns the JWT payload without
// verifying the signature. Any attacker who controls the token controls
// the claims that the application trusts.
func TestRuby_JWT_Vulnerable_JosePeekPayload(t *testing.T) {
	code := `
def show(params)
  token = params[:jwt]
  payload = JOSE::JWT.peek_payload(token)
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for params -> JOSE::JWT.peek_payload()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// jose-ruby JOSE::JWT.peek_protected reads the JOSE header (alg, typ)
// without verification. Trusting the attacker-supplied alg enables
// algorithm-confusion attacks.
func TestRuby_JWT_Vulnerable_JosePeekProtected(t *testing.T) {
	code := `
def inspect_alg(params)
  token = params[:jwt]
  protected_header = JOSE::JWT.peek_protected(token)
end
`
	flows := Analyze(code, "/app/controllers/auth_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for params -> JOSE::JWT.peek_protected()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ruby-jwt v3 JWT::EncodedToken#unverified_payload returns the payload
// without verifying the signature. The receiver is the tainted
// EncodedToken constructed from attacker-controlled input.
func TestRuby_JWT_Vulnerable_EncodedTokenUnverifiedPayload(t *testing.T) {
	code := `
def authenticate(params)
  token = params[:jwt]
  encoded = JWT::EncodedToken.new(token)
  user_id = encoded.unverified_payload["user_id"]
end
`
	flows := Analyze(code, "/app/controllers/api_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for params -> JWT::EncodedToken -> .unverified_payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// jose-ruby JOSE::JWT.verify(key, signed) validates the signature before
// any claim is exposed. A token passed through .verify is no longer
// attacker-controlled for downstream Crypto sinks.
func TestRuby_JWT_Safe_JoseVerify(t *testing.T) {
	code := `
def show(params)
  token = params[:jwt]
  verified, jwt, jws = JOSE::JWT.verify(signing_key, token)
  Rails.cache.write("user:#{jwt.fields['sub']}", jwt.fields)
end
`
	flows := Analyze(code, "/app/controllers/sessions_controller.rb", rules.LangRuby)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust-boundary flow after JOSE::JWT.verify signature check")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
