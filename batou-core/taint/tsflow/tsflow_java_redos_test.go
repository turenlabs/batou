package tsflow

// Tests for the Java ReDoS (CWE-1333) sink family completion.
//
// Java previously modeled only java.util.regex.Pattern.compile() as a
// SnkRegexDoS sink. Several other JDK methods COMPILE A REGEX FROM A STRING
// ARGUMENT internally (no backtracking limit): the static
// Pattern.matches(regex, input) and the String convenience methods matches,
// replaceAll, replaceFirst, and split. When the regex/pattern argument (arg 0)
// is attacker-controlled, each enables catastrophic-backtracking ReDoS.
//
// All sinks key off arg 0 (the PATTERN), so the canonical SAFE idiom of
// validating a tainted value against a CONSTANT pattern (e.g.
// `id.matches("[A-Za-z0-9]+")`) does NOT fire — that constant arg 0 is
// untainted. The negative tests below assert that.

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// TestJava_RegexDoS_PatternMatches_Vulnerable: a request-derived regex flowing
// into the static Pattern.matches(regex, input) must fire SnkRegexDoS.
func TestJava_RegexDoS_PatternMatches_Vulnerable(t *testing.T) {
	code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String re = req.getParameter("re");
    boolean ok = Pattern.matches(re, "haystack");
  }
}
`
	flows := Analyze(code, "/app/H.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Fatalf("expected SnkRegexDoS for getParameter -> Pattern.matches(re, ...); got %d flows", len(flows))
	}
}

// TestJava_RegexDoS_StringMethods_Vulnerable: each String regex method
// (matches / replaceAll / replaceFirst / split) must fire SnkRegexDoS when the
// pattern argument is tainted. The receiver is named `str` so the
// ObjectType:"String" prefix heuristic associates the call.
func TestJava_RegexDoS_StringMethods_Vulnerable(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"String.matches", `boolean ok = str.matches(re);`},
		{"String.replaceAll", `String out = str.replaceAll(re, "x");`},
		{"String.replaceFirst", `String out = str.replaceFirst(re, "x");`},
		{"String.split", `String[] parts = str.split(re);`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String re = req.getParameter("re");
    String str = "some fixed haystack value";
    ` + tc.call + `
  }
}
`
			flows := Analyze(code, "/app/H.java", rules.LangJava)
			if !hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Fatalf("%s: expected SnkRegexDoS for tainted regex arg; got %d flows", tc.name, len(flows))
			}
		})
	}
}

// TestJava_RegexDoS_ConstantPattern_Silent: the safe idiom — validating a
// tainted value against a CONSTANT regex — must NOT fire SnkRegexDoS, because
// arg 0 (the literal pattern) is untainted. This is the FP guard for the family.
func TestJava_RegexDoS_ConstantPattern_Silent(t *testing.T) {
	cases := []struct {
		name string
		call string
	}{
		{"Pattern.matches const", `boolean ok = Pattern.matches("[A-Za-z0-9]+", id);`},
		{"String.matches const", `boolean ok = id.matches("[A-Za-z0-9]+");`},
		{"String.replaceAll const", `String out = id.replaceAll("[\\r\\n]+", "");`},
		{"String.split const", `String[] parts = id.split(",");`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := `
public class H {
  void doGet(HttpServletRequest req) throws Exception {
    String id = req.getParameter("id");
    ` + tc.call + `
  }
}
`
			flows := Analyze(code, "/app/H.java", rules.LangJava)
			if hasTaintFlow(flows, taint.SnkRegexDoS) {
				t.Errorf("%s: constant regex (arg 0 untainted) must NOT fire SnkRegexDoS; got %d flows", tc.name, len(flows))
			}
		})
	}
}
