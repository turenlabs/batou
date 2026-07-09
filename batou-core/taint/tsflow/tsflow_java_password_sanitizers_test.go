package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Spring Security PasswordEncoder family + BouncyCastle KDF sanitizer tests
//
// Pattern: tainted user input → through PasswordEncoder.encode() →
// into a SnkCrypto sink (MessageDigest.getInstance(variableAlg)). The
// sanitizer should break the flow. A matching "Unsanitized" test (without
// the encoder call) verifies the underlying sink-detection still works.
// =========================================================================

func TestJava_Spring_PasswordEncoder_Encode_Sanitized(t *testing.T) {
	// Interface-typed receiver: PasswordEncoder passwordEncoder = ...
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Handler extends HttpServlet {
    private PasswordEncoder passwordEncoder;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        String safe = passwordEncoder.encode(input);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("PasswordEncoder.encode() should neutralize SnkCrypto taint")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJava_Spring_PasswordEncoder_Matches_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Handler extends HttpServlet {
    private PasswordEncoder passwordEncoder;
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        boolean ok = passwordEncoder.matches(input, "$2a$10$abcdefghij");
        String result = String.valueOf(ok);
        MessageDigest.getInstance(result);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("PasswordEncoder.matches() should neutralize SnkCrypto taint")
	}
}

func TestJava_Spring_BCryptPasswordEncoder_Encode_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Handler extends HttpServlet {
    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        String safe = bCryptPasswordEncoder.encode(input);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("BCryptPasswordEncoder.encode() should neutralize SnkCrypto taint")
	}
}

func TestJava_Spring_BCryptPasswordEncoder_Matches_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Handler extends HttpServlet {
    private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        boolean ok = bCryptPasswordEncoder.matches(input, "$2a$10$abc");
        String result = String.valueOf(ok);
        MessageDigest.getInstance(result);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("BCryptPasswordEncoder.matches() should neutralize SnkCrypto taint")
	}
}

func TestJava_Spring_Argon2PasswordEncoder_Encode_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

public class Handler extends HttpServlet {
    private Argon2PasswordEncoder argon2PasswordEncoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        String safe = argon2PasswordEncoder.encode(input);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Argon2PasswordEncoder.encode() should neutralize SnkCrypto taint")
	}
}

func TestJava_Spring_Pbkdf2PasswordEncoder_Encode_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;

public class Handler extends HttpServlet {
    private Pbkdf2PasswordEncoder pbkdf2PasswordEncoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        String safe = pbkdf2PasswordEncoder.encode(input);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Pbkdf2PasswordEncoder.encode() should neutralize SnkCrypto taint")
	}
}

func TestJava_Spring_SCryptPasswordEncoder_Encode_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

public class Handler extends HttpServlet {
    private SCryptPasswordEncoder sCryptPasswordEncoder = new SCryptPasswordEncoder();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        String safe = sCryptPasswordEncoder.encode(input);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("SCryptPasswordEncoder.encode() should neutralize SnkCrypto taint")
	}
}

func TestJava_Spring_DelegatingPasswordEncoder_Encode_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;

public class Handler extends HttpServlet {
    private DelegatingPasswordEncoder delegatingPasswordEncoder =
        (DelegatingPasswordEncoder) PasswordEncoderFactories.createDelegatingPasswordEncoder();
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        String safe = delegatingPasswordEncoder.encode(input);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("DelegatingPasswordEncoder.encode() should neutralize SnkCrypto taint")
	}
}

func TestJava_BouncyCastle_Argon2BytesGenerator_Sanitized(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        Argon2BytesGenerator argon2BytesGenerator = new Argon2BytesGenerator();
        byte[] out = new byte[32];
        argon2BytesGenerator.generateBytes(input.toCharArray(), out, 0, out.length);
        String safe = new String(out);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("Argon2BytesGenerator.generateBytes() should neutralize SnkCrypto taint")
	}
}

func TestJava_BouncyCastle_SCrypt_Generate_Sanitized(t *testing.T) {
	// Static call: SCrypt.generate(...)
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;
import org.bouncycastle.crypto.generators.SCrypt;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String input = request.getParameter("alg");
        byte[] hash = SCrypt.generate(input.getBytes(), new byte[16], 16384, 8, 1, 32);
        String safe = new String(hash);
        MessageDigest.getInstance(safe);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("SCrypt.generate() should neutralize SnkCrypto taint")
	}
}

// =========================================================================
// Negative test: same flow WITHOUT sanitizer should still detect taint.
// Confirms the underlying sink (MessageDigest.getInstance with variable
// algorithm) is wired up correctly so a passing positive test cannot be a
// false negative caused by the sink failing to fire.
// =========================================================================
func TestJava_Spring_PasswordEncoder_Unsanitized_StillDetected(t *testing.T) {
	code := `
import java.security.MessageDigest;
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String alg = request.getParameter("alg");
        MessageDigest.getInstance(alg);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCrypto) {
		t.Error("expected SnkCrypto flow for getParameter -> MessageDigest.getInstance(variable)")
	}
}
