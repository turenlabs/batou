package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// JWT signature verification bypass — auth0 java-jwt JWT.decode
// decodes a token without checking its signature. A tainted token flowing
// into JWT.decode allows an attacker to forge arbitrary claims.
func TestKotlin_JWT_Auth0_DecodeWithoutVerify(t *testing.T) {
	code := `
import com.auth0.jwt.JWT

fun handler(request: HttpServletRequest) {
    val token = request.getHeader("Authorization")
    val decoded = JWT.decode(token)
}
`
	flows := Analyze(code, "/app/JwtHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getHeader -> JWT.decode()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// JWT signature verification bypass — jjwt parseClaimsJwt (note: Jwt vs Jws)
// accepts an unsigned JWT. parseClaimsJws is the signed variant.
func TestKotlin_JWT_JJWT_ParseClaimsJwt_Unsigned(t *testing.T) {
	code := `
import io.jsonwebtoken.Jwts

fun handler(request: HttpServletRequest) {
    val token = request.getHeader("Authorization")
    val claims = Jwts.parser().parseClaimsJwt(token)
}
`
	flows := Analyze(code, "/app/JjwtHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getHeader -> Jwts.parser().parseClaimsJwt()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// JWT signature verification bypass — jjwt parsePlaintextJwt
func TestKotlin_JWT_JJWT_ParsePlaintextJwt(t *testing.T) {
	code := `
import io.jsonwebtoken.Jwts

fun handler(request: HttpServletRequest) {
    val token = request.getParameter("jwt")
    val plain = Jwts.parser().parsePlaintextJwt(token)
}
`
	flows := Analyze(code, "/app/JjwtPlainHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getParameter -> parsePlaintextJwt()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// JWT signature verification bypass — Nimbus PlainJWT.parse reads an unsigned
// JWT (no cryptographic check).
func TestKotlin_JWT_Nimbus_PlainJWT_Parse(t *testing.T) {
	code := `
import com.nimbusds.jwt.PlainJWT

fun handler(request: HttpServletRequest) {
    val token = request.getHeader("X-Token")
    val jwt = PlainJWT.parse(token)
}
`
	flows := Analyze(code, "/app/NimbusHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getHeader -> PlainJWT.parse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
