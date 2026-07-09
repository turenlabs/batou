package gvyast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"strings"
	"testing"
)

func scanGvy(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangGroovy)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.groovy",
		Content:  code,
		Language: rules.LangGroovy,
		Tree:     tree,
	}
	a := &GroovyASTAnalyzer{}
	return a.Scan(ctx)
}

func TestStringExecuteInterpolation(t *testing.T) {
	code := `
class Foo {
    def doStuff(userInput) {
        "ls ${userInput}".execute()
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-001" && f.Severity == rules.Critical {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical command injection finding for string.execute() with interpolation")
	}
}

func TestStringExecuteVariable(t *testing.T) {
	code := `
class Foo {
    def doStuff() {
        def cmd = getCommand()
        cmd.execute()
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for variable.execute()")
	}
}

// TestNonShellExecuteIsNotFlagged covers the FP shape that dominated the
// scan-harness Groovy sample: .execute() on receivers that obviously
// aren't shell strings (statement.execute(sql), future.execute(),
// task.execute(), etc.). The name heuristic should refuse to fire.
func TestNonShellExecuteIsNotFlagged(t *testing.T) {
	code := `
class Foo {
    def doStuff(statement, future, task, request) {
        statement.execute()
        future.execute()
        task.execute()
        request.execute()
    }
}
`
	findings := scanGvy(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-001" {
			t.Errorf("non-shell .execute() should not produce BATOU-GVY-AST-001; got: %s", f.MatchedText)
		}
	}
}

func TestGroovyShellEvaluate(t *testing.T) {
	code := `
class Foo {
    def doStuff(userInput) {
        new GroovyShell().evaluate(userInput)
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-002" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected code injection finding for GroovyShell.evaluate()")
	}
}

func TestRuntimeExec(t *testing.T) {
	code := `
class Foo {
    def doStuff(userInput) {
        Runtime.getRuntime().exec(userInput)
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-003" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected command injection finding for Runtime.exec")
	}
}

func TestGStringSQLDeclaration(t *testing.T) {
	code := `
class Foo {
    def doStuff(userId) {
        def sql = "SELECT * FROM users WHERE id = ${userId}"
    }
}
`
	findings := scanGvy(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-005" && strings.Contains(f.Title, "variable") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for GString SQL variable declaration")
	}
}

func TestGStringSQLSafe(t *testing.T) {
	code := `
class Foo {
    def doStuff() {
        def query = "SELECT * FROM users WHERE id = 1"
    }
}
`
	findings := scanGvy(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-GVY-AST-005" {
			t.Error("unexpected SQL injection finding for safe query without interpolation")
		}
	}
}

func TestSafeCode(t *testing.T) {
	code := `
class Foo {
    def greet(name) {
        return "Hello, ${name}"
    }
}
`
	findings := scanGvy(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe code, got %d", len(findings))
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.groovy",
		Content:  "class Foo {}",
		Language: rules.LangGroovy,
		Tree:     nil,
	}
	a := &GroovyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/main.go",
		Content:  "package main",
		Language: rules.LangGo,
	}
	a := &GroovyASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

// hasRuleCWE reports whether findings contain a finding with the given rule
// ID and CWE.
func hasRuleCWE(findings []rules.Finding, ruleID, cwe string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID && f.CWEID == cwe {
			return true
		}
	}
	return false
}

// --- XXE (CWE-611) ---

func TestXXEXmlSlurperParse(t *testing.T) {
	code := `
class Foo {
    def parse(userInput) {
        return new XmlSlurper().parse(userInput)
    }
}
`
	findings := scanGvy(t, code)
	if !hasRuleCWE(findings, "BATOU-GVY-AST-006", "CWE-611") {
		t.Error("expected XXE finding for new XmlSlurper().parse(userInput)")
	}
}

func TestXXEXmlParserParseText(t *testing.T) {
	code := `
class Foo {
    def parse(xml) {
        return new XmlParser().parseText(xml)
    }
}
`
	findings := scanGvy(t, code)
	if !hasRuleCWE(findings, "BATOU-GVY-AST-006", "CWE-611") {
		t.Error("expected XXE finding for new XmlParser().parseText(xml)")
	}
}

func TestXXEVariableTracked(t *testing.T) {
	code := `
class Foo {
    def parse(xml) {
        def slurper = new XmlSlurper()
        return slurper.parse(xml)
    }
}
`
	findings := scanGvy(t, code)
	if !hasRuleCWE(findings, "BATOU-GVY-AST-006", "CWE-611") {
		t.Error("expected XXE finding for var-tracked slurper.parse(xml)")
	}
}

func TestXXESuppressedWhenHardened(t *testing.T) {
	code := `
class Foo {
    def parse(xml) {
        def slurper = new XmlSlurper()
        slurper.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        return slurper.parse(xml)
    }
}
`
	findings := scanGvy(t, code)
	if hasRuleCWE(findings, "BATOU-GVY-AST-006", "CWE-611") {
		t.Error("XXE finding should be suppressed when disallow-doctype-decl is set")
	}
}

func TestXXENotFiredOnNonParser(t *testing.T) {
	// .parse() on a non-XML-parser receiver must not fire XXE.
	code := `
class Foo {
    def run(data) {
        def n = Integer.parse(data)
        return n
    }
}
`
	findings := scanGvy(t, code)
	if hasRuleCWE(findings, "BATOU-GVY-AST-006", "CWE-611") {
		t.Error("XXE should not fire on Integer.parse")
	}
}

// --- Unsafe deserialization (CWE-502) ---

func TestDeserObjectInputStream(t *testing.T) {
	code := `
class Foo {
    def load(stream) {
        def ois = new ObjectInputStream(stream)
        return ois.readObject()
    }
}
`
	findings := scanGvy(t, code)
	if !hasRuleCWE(findings, "BATOU-GVY-AST-007", "CWE-502") {
		t.Error("expected deserialization finding for ObjectInputStream.readObject()")
	}
}

func TestDeserYamlLoad(t *testing.T) {
	code := `
class Foo {
    def load(input) {
        def yaml = new Yaml()
        return yaml.load(input)
    }
}
`
	findings := scanGvy(t, code)
	if !hasRuleCWE(findings, "BATOU-GVY-AST-007", "CWE-502") {
		t.Error("expected deserialization finding for Yaml.load()")
	}
}

func TestDeserYamlSafeConstructorNotFlagged(t *testing.T) {
	code := `
class Foo {
    def load(input) {
        def yaml = new Yaml(new SafeConstructor())
        return yaml.load(input)
    }
}
`
	findings := scanGvy(t, code)
	if hasRuleCWE(findings, "BATOU-GVY-AST-007", "CWE-502") {
		t.Error("Yaml(new SafeConstructor()).load() must not be flagged as unsafe deserialization")
	}
}

// --- SSRF (CWE-918) ---

func TestSSRFUrlOpenConnection(t *testing.T) {
	code := `
class Foo {
    def fetch(target) {
        return new URL(target).openConnection()
    }
}
`
	findings := scanGvy(t, code)
	if !hasRuleCWE(findings, "BATOU-GVY-AST-008", "CWE-918") {
		t.Error("expected SSRF finding for new URL(target).openConnection()")
	}
}

func TestSSRFLiteralUrlNotFlagged(t *testing.T) {
	// A hardcoded literal URL is not SSRF.
	code := `
class Foo {
    def fetch() {
        return new URL("https://example.com/static").openConnection()
    }
}
`
	findings := scanGvy(t, code)
	if hasRuleCWE(findings, "BATOU-GVY-AST-008", "CWE-918") {
		t.Error("literal-URL openConnection must not be flagged as SSRF")
	}
}
