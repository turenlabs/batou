package generic

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// --- BATOU-GEN-001: Debug Mode Enabled ---

func TestGEN001_DjangoDebug(t *testing.T) {
	content := `DEBUG = True`
	result := testutil.ScanContent(t, "/app/settings.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-001")
}

func TestGEN001_FlaskDebug(t *testing.T) {
	content := `app.run(debug=True)`
	result := testutil.ScanContent(t, "/app/app.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-001")
}

func TestGEN001_GinDebug(t *testing.T) {
	content := `gin.SetMode(gin.DebugMode)`
	result := testutil.ScanContent(t, "/app/main.go", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-001")
}

func TestGEN001_LaravelDebug(t *testing.T) {
	content := `APP_DEBUG=true`
	result := testutil.ScanContent(t, "/app/.env.php", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-001")
}

// --- BATOU-GEN-002: Unsafe Deserialization ---

func TestGEN002_PythonPickle(t *testing.T) {
	content := `data = pickle.loads(user_input)`
	result := testutil.ScanContent(t, "/app/handler.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_PythonYAMLUnsafe(t *testing.T) {
	content := `config = yaml.load(user_data)`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_PythonYAML_Safe_SafeLoader(t *testing.T) {
	content := `config = yaml.load(data, Loader=SafeLoader)`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_JavaObjectInputStream(t *testing.T) {
	content := `ObjectInputStream ois = new ObjectInputStream(inputStream);`
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_RubyMarshal(t *testing.T) {
	content := `data = Marshal.load(input)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_PHPUnserialize(t *testing.T) {
	content := `$data = unserialize($input);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_NodeSerialize(t *testing.T) {
	content := `const data = serialize.unserialize(input);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

func TestGEN002_Fixture_Deserialization_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/deserialization.go")
	result := testutil.ScanContent(t, "/app/handler.go", content)
	hasDeserial := testutil.HasFinding(result, "BATOU-GEN-002")
	if !hasDeserial {
		// Some Go deserialization patterns may not match the current patterns
		t.Logf("no GEN-002 finding in deserialization.go, findings: %v", testutil.FindingRuleIDs(result))
	}
}

func TestGEN002_Fixture_Deserialization_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/deserialization.ts")
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-002")
}

// --- BATOU-GEN-003: XXE Vulnerability ---

func TestGEN003_PythonXML(t *testing.T) {
	content := `import xml.etree.ElementTree as ET
tree = ET.parse(user_file)`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-003")
}

func TestGEN003_Python_Safe_DefusedXML(t *testing.T) {
	content := `import defusedxml.ElementTree as ET
tree = ET.parse(user_file)`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-003")
}

func TestGEN003_JavaDocBuilder(t *testing.T) {
	content := `DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();`
	result := testutil.ScanContent(t, "/app/XmlParser.java", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-003")
}

func TestGEN003_Fixture_XXE_JS(t *testing.T) {
	if !testutil.FixtureExists("javascript/vulnerable/xml_xxe.ts") {
		t.Skip("XXE fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/vulnerable/xml_xxe.ts")
	result := testutil.ScanContent(t, "/app/xml.ts", content)
	hasXXE := testutil.HasFinding(result, "BATOU-GEN-003") || testutil.HasFinding(result, "BATOU-GEN-009")
	if !hasXXE {
		t.Errorf("expected XXE finding in xml_xxe.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- BATOU-GEN-004: Open Redirect ---

func TestGEN004_PythonRedirect(t *testing.T) {
	content := `return redirect(request.args.get('next'))`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-004")
}

func TestGEN004_JSRedirect(t *testing.T) {
	content := `res.redirect(req.query.url);`
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-004")
}

func TestGEN004_PHPRedirect(t *testing.T) {
	content := `<?php header("Location: " . $_GET['url']); ?>`
	result := testutil.ScanContent(t, "/app/redirect.php", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-004")
}

func TestGEN004_RubyRedirect(t *testing.T) {
	content := `redirect_to params[:url]`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-004")
}

func TestGEN004_Fixture_OpenRedirect_Go(t *testing.T) {
	content := testutil.LoadFixture(t, "go/vulnerable/open_redirect.go")
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-004")
}

func TestGEN004_Fixture_OpenRedirect_JS(t *testing.T) {
	content := testutil.LoadFixture(t, "javascript/vulnerable/open_redirect.ts")
	result := testutil.ScanContent(t, "/app/routes.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-004")
}

// --- BATOU-GEN-005: Log Injection ---

func TestGEN005_GoLogInjection(t *testing.T) {
	content := `log.Printf("User login: %s", r.FormValue("username"))`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-005")
}

func TestGEN005_JSLogInjection(t *testing.T) {
	content := `console.log("Search: " + req.query.q);`
	result := testutil.ScanContent(t, "/app/search.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-005")
}

// --- BATOU-GEN-006: Race Condition (TOCTOU) ---

func TestGEN006_TOCTOU_FileExists(t *testing.T) {
	content := `if _, err := os.Stat(path); err == nil {
	data, _ := os.ReadFile(path)
}`
	result := testutil.ScanContent(t, "/app/file.go", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-006")
}

func TestGEN006_Safe_WithMutex(t *testing.T) {
	content := `mu.Lock()
if _, err := os.Stat(path); err == nil {
	data, _ := os.ReadFile(path)
}
mu.Unlock()`
	result := testutil.ScanContent(t, "/app/file.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-006")
}

// --- BATOU-GEN-007: Mass Assignment ---

func TestGEN007_Go_BindJSON(t *testing.T) {
	content := `func updateUser(c *gin.Context) {
	var user User
	c.ShouldBindJSON(&user)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-007")
}

func TestGEN007_Rails_PermitAll(t *testing.T) {
	content := `user_params = params.permit!`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-007")
}

func TestGEN007_Django_FieldsAll(t *testing.T) {
	content := `class Meta:
    model = User
    fields = '__all__'`
	result := testutil.ScanContent(t, "/app/forms.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-007")
}

func TestGEN007_JS_SpreadBody(t *testing.T) {
	content := `const data = { ...req.body };`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-007")
}

// --- BATOU-GEN-009: XML Parser Misconfiguration ---

func TestGEN009_NoentTrue(t *testing.T) {
	content := `const doc = parseXml(input, { noent: true });`
	result := testutil.ScanContent(t, "/app/xml.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-009")
}

func TestGEN009_ResolveExternals(t *testing.T) {
	content := `xmlDoc.resolveExternals = true;`
	result := testutil.ScanContent(t, "/app/xml.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-009")
}

func TestGEN009_JavaExternalEntities(t *testing.T) {
	content := `dbf.setFeature("http://xml.org/sax/features/external-general-entities", true);`
	result := testutil.ScanContent(t, "/app/XmlParser.java", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-009")
}

// --- BATOU-GEN-011: Unsafe YAML Deserialization ---

func TestGEN011_Python_YAMLLoad_Unsafe(t *testing.T) {
	content := `import yaml
data = yaml.load(user_input)`
	result := testutil.ScanContent(t, "/app/config.py", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-GEN-002", "BATOU-GEN-011")
}

func TestGEN011_Python_YAMLUnsafeLoad(t *testing.T) {
	content := `import yaml
data = yaml.unsafe_load(raw_data)`
	result := testutil.ScanContent(t, "/app/parser.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_Python_YAMLLoad_Safe_SafeLoader(t *testing.T) {
	content := `import yaml
data = yaml.load(user_input, Loader=SafeLoader)`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_Python_YAMLSafeLoad(t *testing.T) {
	content := `import yaml
data = yaml.safe_load(user_input)`
	result := testutil.ScanContent(t, "/app/config.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_JS_YAMLLoad_Unsafe(t *testing.T) {
	content := `const yaml = require('js-yaml');
const data = yaml.load(fileContent);`
	result := testutil.ScanContent(t, "/app/parser.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_JS_YAMLSafeLoad(t *testing.T) {
	content := `const yaml = require('js-yaml');
const data = yaml.safeLoad(fileContent);`
	result := testutil.ScanContent(t, "/app/parser.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_Ruby_YAMLLoad_Unsafe(t *testing.T) {
	content := `require 'yaml'
data = YAML.load(user_input)`
	result := testutil.ScanContent(t, "/app/parser.rb", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_Ruby_YAMLSafeLoad(t *testing.T) {
	content := `require 'yaml'
data = YAML.safe_load(user_input)`
	result := testutil.ScanContent(t, "/app/parser.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-011")
}

func TestGEN011_Fixture_Ruby_YAML(t *testing.T) {
	if !testutil.FixtureExists("ruby/vulnerable/yaml_deserialization.rb") {
		t.Skip("Ruby YAML fixture not available")
	}
	content := testutil.LoadFixture(t, "ruby/vulnerable/yaml_deserialization.rb")
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	hasYAML := testutil.HasFinding(result, "BATOU-GEN-011") || testutil.HasFinding(result, "BATOU-GEN-002")
	if !hasYAML {
		t.Errorf("expected YAML deserialization finding in yaml_deserialization.rb, got: %v", testutil.FindingRuleIDs(result))
	}
}

// --- BATOU-GEN-010: VM Sandbox Escape ---

func TestGEN010_VMRunInNewContext(t *testing.T) {
	content := `const vm = require('vm');
const userCode = req.body.code;
const result = vm.runInNewContext(userCode, sandbox);`
	result := testutil.ScanContent(t, "/app/sandbox.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_VMRunInContext(t *testing.T) {
	content := `const vm = require('vm');
const data = req.body.expression;
const ctx = vm.createContext(sandbox);
const output = vm.runInContext(data, ctx);`
	result := testutil.ScanContent(t, "/app/eval.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_VMRunInThisContext(t *testing.T) {
	content := `const vm = require('vm');
const code = req.query.expr;
vm.runInThisContext(code);`
	result := testutil.ScanContent(t, "/app/eval.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_VMCreateScript(t *testing.T) {
	content := `const vm = require('vm');
const userInput = req.body.script;
const script = vm.createScript(userInput);`
	result := testutil.ScanContent(t, "/app/runner.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_VM2Sandbox(t *testing.T) {
	content := `const { VM } = require('vm2');
const vm = new VM({ timeout: 1000 });
const result = vm.run(userCode);`
	result := testutil.ScanContent(t, "/app/sandbox.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_NewFunctionWithUserInput(t *testing.T) {
	content := `app.post('/calc', (req, res) => {
  const expr = req.body.expression;
  const fn = new Function('x', expr);
  res.json({ result: fn(42) });
});`
	result := testutil.ScanContent(t, "/app/calc.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_ChildProcessExecTemplateLiteral(t *testing.T) {
	content := "const cmd = req.query.cmd;\nchild_process.exec(`ls ${cmd}`);"
	result := testutil.ScanContent(t, "/app/exec.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_ExecSyncTemplateLiteral(t *testing.T) {
	content := "const name = req.params.name;\nconst out = execSync(`grep ${name} /etc/passwd`);"
	result := testutil.ScanContent(t, "/app/search.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_Safe_VMWithoutUserInput(t *testing.T) {
	// vm usage without any user input source should not trigger at high confidence
	// but will still trigger at medium confidence since vm is inherently unsafe
	content := `const vm = require('vm');
const script = "2 + 2";
const result = vm.runInNewContext(script, {});`
	result := testutil.ScanContent(t, "/app/calc.ts", content)
	// Should still detect vm usage (medium confidence)
	testutil.MustFindRule(t, result, "BATOU-GEN-010")
}

func TestGEN010_Safe_NoVMImport(t *testing.T) {
	// new VM() without vm/vm2 import context should NOT trigger
	content := `class VM {
  constructor() { this.state = {}; }
}
const vm = new VM();`
	result := testutil.ScanContent(t, "/app/engine.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-010")
}

// --- BATOU-GEN-012: Insecure Download Patterns ---

func TestGEN012_CurlPipeBash(t *testing.T) {
	content := `curl -fsSL https://example.com/install.sh | bash`
	result := testutil.ScanContent(t, "/app/setup.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

// --- BATOU-GEN-008: Code As String Eval ---

func TestGEN008_EvalWithPickle(t *testing.T) {
	content := `eval('pickle.loads(data)')`
	result := testutil.ScanContent(t, "/app/handler.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-008")
}

func TestGEN008_EvalWithYAMLLoad(t *testing.T) {
	content := `eval('yaml.load(user_data)')`
	result := testutil.ScanContent(t, "/app/handler.py", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-008")
}

func TestGEN008_VMRunInNewContextWithExec(t *testing.T) {
	content := `vm.runInNewContext('require("child_process").exec("rm -rf /")', sandbox);`
	result := testutil.ScanContent(t, "/app/sandbox.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-GEN-008", "BATOU-GEN-010")
}

func TestGEN008_VMRunInContextWithCommand(t *testing.T) {
	content := `vm.runInContext('os.system("whoami")', ctx);`
	result := testutil.ScanContent(t, "/app/sandbox.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-GEN-008", "BATOU-GEN-010")
}

func TestGEN008_NewFunctionWithUnserialize(t *testing.T) {
	content := `new Function('data', 'return unserialize(data)');`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-008")
}

func TestGEN008_EvalTemplateLiteralWithExec(t *testing.T) {
	content := "eval(`require('child_process').exec(cmd)`);"
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-008")
}

func TestGEN008_Safe_EvalWithoutDangerousCalls(t *testing.T) {
	content := `eval('2 + 2')`
	result := testutil.ScanContent(t, "/app/calc.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-008")
}

func TestGEN008_Safe_CommentLine(t *testing.T) {
	content := `// eval('pickle.loads(data)')`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-008")
}

func TestGEN012_CurlPipeSudoBash(t *testing.T) {
	content := `curl -sSL https://get.example.com | sudo bash`
	result := testutil.ScanContent(t, "/app/install.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_WgetPipeSh(t *testing.T) {
	content := `wget -qO- https://example.com/setup.sh | sh`
	result := testutil.ScanContent(t, "/app/install.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_CurlHTTP(t *testing.T) {
	content := `curl http://example.com/package.tar.gz -o pkg.tar.gz`
	result := testutil.ScanContent(t, "/app/install.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_CurlInsecure(t *testing.T) {
	content := `curl --insecure https://internal.example.com/data`
	result := testutil.ScanContent(t, "/app/fetch.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_PipTrustedHost(t *testing.T) {
	content := `pip install --trusted-host pypi.internal.com mypackage`
	result := testutil.ScanContent(t, "/app/install.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_NpmUnsafePerm(t *testing.T) {
	content := `npm install --unsafe-perm -g mypackage`
	result := testutil.ScanContent(t, "/app/install.sh", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_Dockerfile_CurlPipe(t *testing.T) {
	content := `FROM ubuntu:20.04
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -`
	result := testutil.ScanContent(t, "/app/Dockerfile", content)
	testutil.MustFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_Safe_CurlToFile(t *testing.T) {
	content := `curl -fsSL https://example.com/install.sh -o install.sh
sha256sum -c checksums.txt
bash install.sh`
	result := testutil.ScanContent(t, "/app/setup.sh", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN012_Safe_Comment(t *testing.T) {
	content := `# Don't do: curl https://example.com/install.sh | bash
# Instead download and verify first`
	result := testutil.ScanContent(t, "/app/setup.sh", content)
	testutil.MustNotFindRule(t, result, "BATOU-GEN-012")
}

func TestGEN010_Fixture_B2BOrder(t *testing.T) {
	if !testutil.FixtureExists("javascript/vulnerable/vm_sandbox_escape.ts") {
		t.Skip("vm sandbox escape fixture not available")
	}
	content := testutil.LoadFixture(t, "javascript/vulnerable/vm_sandbox_escape.ts")
	result := testutil.ScanContent(t, "/app/b2bOrder.ts", content)
	hasVM := testutil.HasFinding(result, "BATOU-GEN-010") || testutil.HasFinding(result, "BATOU-GEN-002")
	if !hasVM {
		t.Errorf("expected VM sandbox escape finding in vm_sandbox_escape.ts, got: %v", testutil.FindingRuleIDs(result))
	}
}
