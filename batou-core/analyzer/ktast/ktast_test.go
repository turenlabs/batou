package ktast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"strings"
	"testing"
)

func scanKt(t *testing.T, code string) []rules.Finding {
	t.Helper()
	tree := ast.Parse([]byte(code), rules.LangKotlin)
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.kt",
		Content:  code,
		Language: rules.LangKotlin,
		Tree:     tree,
	}
	a := &KotlinASTAnalyzer{}
	return a.Scan(ctx)
}

func TestRawQueryConcat(t *testing.T) {
	code := `
fun getUser(db: SQLiteDatabase, userId: String) {
    db.rawQuery("SELECT * FROM users WHERE id = " + userId, null)
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-KT-AST-001" {
			found = true
			if f.Severity != rules.Critical {
				t.Errorf("expected Critical, got %s", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected SQL injection finding for rawQuery with concat")
	}
}

func TestRawQuerySafe(t *testing.T) {
	code := `
fun getUser(db: SQLiteDatabase, userId: String) {
    db.rawQuery("SELECT * FROM users WHERE id = ?", arrayOf(userId))
}
`
	findings := scanKt(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-KT-AST-001" {
			t.Error("unexpected SQL injection finding for parameterized query")
		}
	}
}

func TestAddJavascriptInterface(t *testing.T) {
	code := `
fun setupWebView(webView: WebView) {
    webView.addJavascriptInterface(bridge, "Android")
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-KT-AST-002" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding for addJavascriptInterface")
	}
}

func TestSensitiveSharedPrefs(t *testing.T) {
	code := `
fun save(prefs: SharedPreferences) {
    prefs.edit().putString("password", password).apply()
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-KT-AST-003" {
			found = true
			if !strings.Contains(f.Title, "SharedPreferences") {
				t.Errorf("expected SharedPreferences in title, got %s", f.Title)
			}
			break
		}
	}
	if !found {
		t.Error("expected finding for sensitive data in SharedPreferences")
	}
}

func TestNonSensitiveSharedPrefs(t *testing.T) {
	code := `
fun save(prefs: SharedPreferences) {
    prefs.edit().putString("theme", "dark").apply()
}
`
	findings := scanKt(t, code)
	for _, f := range findings {
		if f.RuleID == "BATOU-KT-AST-003" {
			t.Error("unexpected finding for non-sensitive SharedPreferences key")
		}
	}
}

func TestRuntimeExec(t *testing.T) {
	code := `
fun runCommand(cmd: String) {
    Runtime.getRuntime().exec(cmd)
}
`
	findings := scanKt(t, code)
	found := false
	for _, f := range findings {
		if f.RuleID == "BATOU-KT-AST-004" {
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

func hasRule(findings []rules.Finding, id string) bool {
	for _, f := range findings {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func TestUnsafeDeserialization(t *testing.T) {
	code := `
fun handle(req: HttpServletRequest): Any {
    val ois = ObjectInputStream(req.inputStream)
    return ois.readObject()
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-005") {
		t.Error("expected CWE-502 finding for ObjectInputStream constructor")
	}
}

func TestUnsafeDeserializationXMLDecoder(t *testing.T) {
	code := `
fun handle(req: HttpServletRequest): Any {
    val dec = XMLDecoder(req.inputStream)
    return dec.readObject()
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-005") {
		t.Error("expected CWE-502 finding for XMLDecoder constructor")
	}
}

func TestDeserializationNoFalsePositiveOnReadValue(t *testing.T) {
	// A typed readValue without default typing is not flagged structurally.
	code := `
fun parse(mapper: ObjectMapper, data: String): MyDto {
    return mapper.readValue(data, MyDto::class.java)
}
`
	findings := scanKt(t, code)
	if hasRule(findings, "BATOU-KT-AST-005") || hasRule(findings, "BATOU-KT-AST-006") {
		t.Error("unexpected deserialization finding for safe typed readValue")
	}
}

func TestJacksonDefaultTyping(t *testing.T) {
	code := `
fun config(mapper: ObjectMapper) {
    mapper.enableDefaultTyping()
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-006") {
		t.Error("expected CWE-502 finding for Jackson enableDefaultTyping")
	}
}

func TestJacksonActivateDefaultTyping(t *testing.T) {
	code := `
fun config(mapper: ObjectMapper, ptv: PolymorphicTypeValidator) {
    mapper.activateDefaultTyping(ptv)
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-006") {
		t.Error("expected CWE-502 finding for Jackson activateDefaultTyping")
	}
}

func TestSSTIConcat(t *testing.T) {
	code := `
fun render(engine: TemplateEngine, ctx: Context, name: String): String {
    return engine.process("Hello " + name, ctx)
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-007") {
		t.Error("expected CWE-1336 SSTI finding for concatenated template source")
	}
}

func TestSSTIInterpolation(t *testing.T) {
	code := `
fun render(handlebars: Handlebars, name: String) {
    handlebars.compileInline("Hi ${name}")
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-007") {
		t.Error("expected CWE-1336 SSTI finding for interpolated template source")
	}
}

func TestSSTISafeStaticTemplate(t *testing.T) {
	code := `
fun render(engine: TemplateEngine, ctx: Context): String {
    return engine.process("welcome-page", ctx)
}
`
	findings := scanKt(t, code)
	if hasRule(findings, "BATOU-KT-AST-007") {
		t.Error("unexpected SSTI finding for static literal template name")
	}
}

func TestSSRFDynamicURL(t *testing.T) {
	code := `
fun fetch(target: String): String {
    return URL(target).openConnection().getInputStream().bufferedReader().readText()
}
`
	findings := scanKt(t, code)
	if !hasRule(findings, "BATOU-KT-AST-008") {
		t.Error("expected CWE-918 SSRF finding for URL built from variable")
	}
}

func TestSSRFSafeLiteralURL(t *testing.T) {
	code := `
fun health(): String {
    return URL("https://internal.example.com/health").readText()
}
`
	findings := scanKt(t, code)
	if hasRule(findings, "BATOU-KT-AST-008") {
		t.Error("unexpected SSRF finding for hardcoded literal URL")
	}
}

func TestSafeCode(t *testing.T) {
	code := `
fun greet(name: String): String {
    return "Hello, $name!"
}
`
	findings := scanKt(t, code)
	if len(findings) != 0 {
		t.Errorf("expected no findings for safe code, got %d", len(findings))
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/Handler.kt",
		Content:  "fun main() {}",
		Language: rules.LangKotlin,
		Tree:     nil,
	}
	a := &KotlinASTAnalyzer{}
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
	a := &KotlinASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}
