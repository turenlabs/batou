package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C# JWT signature-bypass (CWE-345) tests
// =========================================================================

func TestCSharp_JWT_HandlerReadJwtToken(t *testing.T) {
	code := `
using System;
using System.IdentityModel.Tokens.Jwt;

public class Handler {
    public string Handle() {
        string tokenString = Console.ReadLine();
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(tokenString);
        return token.Subject;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for Console.ReadLine -> JwtSecurityTokenHandler.ReadJwtToken")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_JWT_JoseJWTPayload(t *testing.T) {
	code := `
using System;

public class Handler {
    public string Handle() {
        string tokenString = Console.ReadLine();
        string json = Jose.JWT.Payload(tokenString);
        return json;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for Console.ReadLine -> Jose.JWT.Payload")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_JWT_JoseJWTHeaders(t *testing.T) {
	code := `
using System;

public class Handler {
    public string Handle() {
        string tokenString = Console.ReadLine();
        var headers = Jose.JWT.Headers(tokenString);
        return headers.ToString();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for Console.ReadLine -> Jose.JWT.Headers")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Sanitizer tests — verify proper JWT verification suppresses findings
// =========================================================================

func TestCSharp_JWT_Sanitized_HandlerValidateToken(t *testing.T) {
	code := `
using System;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

public class Handler {
    public void Handle(TokenValidationParameters validationParameters) {
        string tokenString = Console.ReadLine();
        var handler = new JwtSecurityTokenHandler();
        SecurityToken validatedToken;
        var principal = handler.ValidateToken(tokenString, validationParameters, out validatedToken);
        Console.WriteLine(principal.Identity.Name);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected NO SnkCrypto flow when token is verified via JwtSecurityTokenHandler.ValidateToken")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_JWT_Sanitized_JoseJWTDecode(t *testing.T) {
	code := `
using System;

public class Handler {
    public string Handle(byte[] key) {
        string tokenString = Console.ReadLine();
        string json = Jose.JWT.Decode(tokenString, key, Jose.JwsAlgorithm.HS256);
        return json;
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected NO SnkCrypto flow when token is verified via Jose.JWT.Decode(token, key, alg)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
