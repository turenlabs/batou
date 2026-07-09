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
func TestJava_JWT_Auth0_DecodeWithoutVerify(t *testing.T) {
	code := `
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import javax.servlet.http.*;

public class JwtHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("Authorization");
        DecodedJWT decoded = JWT.decode(token);
    }
}
`
	flows := Analyze(code, "/app/JwtHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getHeader -> JWT.decode()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// JWT signature verification bypass — jjwt parseClaimsJwt (note: Jwt vs Jws)
// accepts an unsigned JWT. parseClaimsJws is the signed variant.
func TestJava_JWT_JJWT_ParseClaimsJwtUnsigned(t *testing.T) {
	code := `
import io.jsonwebtoken.Jwts;
import javax.servlet.http.*;

public class JwtHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getParameter("token");
        Object claims = Jwts.parser().parseClaimsJwt(token);
    }
}
`
	flows := Analyze(code, "/app/JwtHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getParameter -> parseClaimsJwt()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// JWT signature verification bypass — jjwt parsePlaintextJwt accepts a
// plaintext (unsigned) JWT. parsePlaintextJws is the signed variant.
func TestJava_JWT_JJWT_ParsePlaintextJwtUnsigned(t *testing.T) {
	code := `
import io.jsonwebtoken.Jwts;
import javax.servlet.http.*;

public class JwtHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) {
        String token = request.getHeader("X-Token");
        Object jwt = Jwts.parser().parsePlaintextJwt(token);
    }
}
`
	flows := Analyze(code, "/app/JwtHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getHeader -> parsePlaintextJwt()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// JWT signature verification bypass — Nimbus PlainJWT.parse reads an
// unsigned JWT. SignedJWT.parse followed by .verify(verifier) is the safe
// equivalent.
func TestJava_JWT_Nimbus_PlainJWTParse(t *testing.T) {
	code := `
import com.nimbusds.jwt.PlainJWT;
import javax.servlet.http.*;

public class JwtHandler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String token = request.getParameter("jwt");
        PlainJWT jwt = PlainJWT.parse(token);
    }
}
`
	flows := Analyze(code, "/app/JwtHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected JWT signature-bypass flow for getParameter -> PlainJWT.parse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
