package taintrule

import (
	"os"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// finding is a tiny constructor for synthetic taint findings used to drive
// the language-specific FP-suppression filters directly. The filters key on
// LineNumber (1-based), CWEID and RuleID, so those are the fields we set.
func finding(line int, cwe, ruleID string) rules.Finding {
	return rules.Finding{
		RuleID:     ruleID,
		CWEID:      cwe,
		LineNumber: line,
	}
}

// findingLines returns the LineNumbers of the kept findings, for stable
// assertions independent of other Finding fields.
func keptLines(fs []rules.Finding) []int {
	out := make([]int, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.LineNumber)
	}
	return out
}

// =========================================================================
// ssaflowEnabled — routing/env decision
// =========================================================================

func TestSSAFlowEnabled(t *testing.T) {
	cases := []struct {
		name string
		val  string
		set  bool
		want bool
	}{
		{"unset defaults on", "", false, true},
		{"empty string defaults on", "", true, true},
		{"explicit 0 off", "0", true, false},
		{"false off", "false", true, false},
		{"FALSE case-insensitive off", "FALSE", true, false},
		{"off off", "off", true, false},
		{"Off mixed-case off", "Off", true, false},
		{"no off", "no", true, false},
		{"NO uppercase off", "NO", true, false},
		{"1 on", "1", true, true},
		{"true on", "true", true, true},
		{"on on", "on", true, true},
		{"yes on", "yes", true, true},
		{"garbage value defaults on", "banana", true, true},
	}

	orig, had := os.LookupEnv("BATOU_SSAFLOW")
	t.Cleanup(func() {
		if had {
			// batou:ignore trust_boundary -- test save/restore: writes back the same env var's prior value, not untrusted input
			_ = os.Setenv("BATOU_SSAFLOW", orig)
		} else {
			_ = os.Unsetenv("BATOU_SSAFLOW")
		}
	})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				_ = os.Setenv("BATOU_SSAFLOW", tc.val)
			} else {
				_ = os.Unsetenv("BATOU_SSAFLOW")
			}
			if got := ssaflowEnabled(); got != tc.want {
				t.Errorf("ssaflowEnabled() with %q (set=%v) = %v, want %v", tc.val, tc.set, got, tc.want)
			}
		})
	}
}

// =========================================================================
// Rule metadata
// =========================================================================

func TestTaintRuleMetadata(t *testing.T) {
	r := &TaintRule{}
	if r.ID() != "BATOU-TAINT" {
		t.Errorf("ID() = %q", r.ID())
	}
	if r.Name() == "" {
		t.Error("Name() should be non-empty")
	}
	if r.Description() == "" {
		t.Error("Description() should be non-empty")
	}
	if r.DefaultSeverity() != rules.Critical {
		t.Errorf("DefaultSeverity() = %v, want Critical", r.DefaultSeverity())
	}
	langs := r.Languages()
	if len(langs) == 0 {
		t.Fatal("Languages() returned empty list")
	}
	// Spot-check that a representative spread of languages is advertised.
	want := map[rules.Language]bool{
		rules.LangGo: false, rules.LangPython: false, rules.LangJava: false,
		rules.LangZig: false, rules.LangShell: false,
	}
	for _, l := range langs {
		if _, ok := want[l]; ok {
			want[l] = true
		}
	}
	for l, seen := range want {
		if !seen {
			t.Errorf("Languages() missing expected language %v", l)
		}
	}
}

// =========================================================================
// Out-of-range line handling (shared across all filters)
// =========================================================================

func TestFilters_LineOutOfRange_Kept(t *testing.T) {
	content := "line1\nline2\n"
	// Findings whose LineNumber is out of range must be kept verbatim by
	// the py/java/js filters (they cannot inspect surrounding context).
	fs := []rules.Finding{
		finding(0, "89", "BATOU-TAINT"),   // lineIdx -1
		finding(999, "89", "BATOU-TAINT"), // beyond EOF
	}

	if got := pyFilterTaintFindings(content, fs); len(got) != 2 {
		t.Errorf("py: out-of-range findings dropped: kept %v", keptLines(got))
	}
	if got := javaFilterTaintFindings(content, fs); len(got) != 2 {
		t.Errorf("java: out-of-range findings dropped: kept %v", keptLines(got))
	}
	if got := jsFilterTaintFindings(content, fs); len(got) != 2 {
		t.Errorf("js: out-of-range findings dropped: kept %v", keptLines(got))
	}
}

// =========================================================================
// Python filter — pyFilterTaintFindings + helpers
// =========================================================================

func TestPyFilter_PlainVulnerable_Kept(t *testing.T) {
	// A straightforward tainted flow with no guard: must be kept.
	content := strings.Join([]string{
		"import os",
		"name = request.args.get('n')",
		"os.system('echo ' + name)",
	}, "\n")
	fs := []rules.Finding{finding(3, "78", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Fatalf("expected vulnerable finding kept, got %d", len(got))
	}
}

func TestPyFilter_DeterministicArithmeticIf_Suppressed(t *testing.T) {
	// Arithmetic-if + literal branch assignment → deterministic conditional.
	content := strings.Join([]string{
		"def handler(num, param):",
		"    if 7 * 42 - num > 200:",
		"        bar = 'safe'",
		"    else:",
		"        bar = param",
		"    os.system(bar)",
	}, "\n")
	fs := []rules.Finding{finding(6, "78", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("deterministic arithmetic-if should suppress finding, kept %v", keptLines(got))
	}
}

func TestPyFilter_TernaryArithmetic_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"def handler(num, param):",
		"    bar = 'safe' if 7 * 18 + num > 200 else param",
		"    os.system(bar)",
	}, "\n")
	fs := []rules.Finding{finding(3, "78", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("ternary-arithmetic guard should suppress finding, kept %v", keptLines(got))
	}
}

func TestPyFilter_MatchOnConstSubscript_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"def handler(param):",
		"    possible = 'ABCDEF'",
		"    guess = possible[1]",
		"    match guess:",
		"        case 'B':",
		"            bar = 'literal'",
		"    os.system(bar)",
	}, "\n")
	fs := []rules.Finding{finding(7, "78", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("match-on-const-subscript should suppress finding, kept %v", keptLines(got))
	}
}

func TestPyFilter_YAMLSafeLoad_Suppressed(t *testing.T) {
	// CWE-502 deserialization with yaml.safe_load on the sink line is safe.
	content := strings.Join([]string{
		"import yaml",
		"data = yaml.safe_load(request.data)",
	}, "\n")
	fs := []rules.Finding{finding(2, "502", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("yaml.safe_load should suppress CWE-502, kept %v", keptLines(got))
	}
}

func TestPyFilter_YAMLUnsafeLoad_Kept(t *testing.T) {
	content := strings.Join([]string{
		"import yaml",
		"data = yaml.load(request.data)",
	}, "\n")
	fs := []rules.Finding{finding(2, "502", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Errorf("yaml.load (unsafe) should NOT be suppressed, kept %v", keptLines(got))
	}
}

func TestPyFilter_EvalGuard_Suppressed(t *testing.T) {
	// CWE-94 code injection with a startswith guard before eval.
	content := strings.Join([]string{
		"def handler(expr):",
		"    if not expr.startswith('safe_'):",
		"        return",
		"    eval(expr)",
	}, "\n")
	fs := []rules.Finding{finding(4, "94", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("eval guard should suppress CWE-94, kept %v", keptLines(got))
	}
}

func TestPyFilter_URLValidation_Suppressed(t *testing.T) {
	// CWE-601 open redirect with urlparse validation.
	content := strings.Join([]string{
		"def handler(target):",
		"    parsed = urlparse(target)",
		"    if parsed.netloc not in ALLOWED:",
		"        return",
		"    redirect(target)",
	}, "\n")
	fs := []rules.Finding{finding(5, "601", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("urlparse validation should suppress CWE-601, kept %v", keptLines(got))
	}
}

func TestPyFilter_SafeDictKey_Suppressed(t *testing.T) {
	// Taint finding whose sink variable resolves to a safe dict key.
	content := strings.Join([]string{
		"config = {}",
		"config['keyA'] = 'literal-value'",
		"bar = config['keyA']",
		"os.system(f'{bar}')",
	}, "\n")
	fs := []rules.Finding{finding(4, "78", "BATOU-TAINT")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("safe dict-key resolution should suppress, kept %v", keptLines(got))
	}
}

func TestPyFilter_NonTaintRule_SkipsDictConfigCheck(t *testing.T) {
	// The dict/config safety check is gated on the BATOU-TAINT rule prefix.
	// A non-taint rule with the same safe-dict structure should be kept
	// (the gate only runs for taint findings).
	content := strings.Join([]string{
		"config = {}",
		"config['keyA'] = 'literal-value'",
		"bar = config['keyA']",
		"os.system(f'{bar}')",
	}, "\n")
	fs := []rules.Finding{finding(4, "78", "BATOU-INJ-001")}
	got := pyFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Errorf("non-taint rule should bypass dict/config suppression, kept %v", keptLines(got))
	}
}

// =========================================================================
// Java filter — javaFilterTaintFindings + helpers
// =========================================================================

func TestJavaFilter_PlainVulnerable_Kept(t *testing.T) {
	content := strings.Join([]string{
		"public void handle(HttpServletRequest req) {",
		"    String p = req.getParameter(\"q\");",
		"    Runtime.getRuntime().exec(p);",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(3, "78", "BATOU-TAINT")}
	got := javaFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Fatalf("expected vulnerable Java finding kept, got %d", len(got))
	}
}

func TestJavaFilter_ArithmeticIf_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"public void handle(int num, String param) {",
		"    String bar;",
		"    if ((7 * 42) - num > 200) {",
		"        bar = \"safe\";",
		"    } else {",
		"        bar = param;",
		"    }",
		"    Runtime.getRuntime().exec(bar);",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(8, "78", "BATOU-TAINT")}
	got := javaFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("Java arithmetic-if should suppress finding, kept %v", keptLines(got))
	}
}

func TestJavaFilter_TernaryArithmetic_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"public void handle(int num, String param) {",
		"    String bar = (7 * 18 + num > 200) ? \"safe\" : param;",
		"    Runtime.getRuntime().exec(bar);",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(3, "78", "BATOU-TAINT")}
	got := javaFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("Java ternary-arithmetic should suppress finding, kept %v", keptLines(got))
	}
}

func TestJavaFilter_SwitchOnConst_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"public void handle(String param) {",
		"    char[] arr = \"ABCDEF\".toCharArray();",
		"    String bar = param;",
		"    switch (arr[2]) {",
		"        case 'C':",
		"            bar = \"literal\";",
		"            break;",
		"    }",
		"    Runtime.getRuntime().exec(bar);",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(9, "78", "BATOU-TAINT")}
	got := javaFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("Java switch-on-const should suppress finding, kept %v", keptLines(got))
	}
}

// =========================================================================
// JavaScript/TypeScript filter — jsFilterTaintFindings + helpers
// =========================================================================

func TestJsFilter_PlainVulnerable_Kept(t *testing.T) {
	content := strings.Join([]string{
		"app.get('/u', (req, res) => {",
		"  const id = req.query.id;",
		"  db.query('SELECT * FROM users WHERE id = ' + id);",
		"});",
	}, "\n")
	fs := []rules.Finding{finding(3, "89", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Fatalf("expected vulnerable JS SQLi kept, got %d", len(got))
	}
}

func TestJsFilter_SQL_ParamQuery_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const id = req.query.id;",
		"db.query('SELECT * FROM users WHERE id = ?', [id]);",
	}, "\n")
	fs := []rules.Finding{finding(2, "89", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("parameterized query should suppress CWE-89, kept %v", keptLines(got))
	}
}

func TestJsFilter_SQL_KnexBuilder_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const id = req.query.id;",
		"knex('users').where({ id }).then(rows => res.json(rows));",
	}, "\n")
	fs := []rules.Finding{finding(2, "89", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("knex builder should suppress CWE-89, kept %v", keptLines(got))
	}
}

func TestJsFilter_XSS_Sanitizer_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const raw = req.query.html;",
		"el.innerHTML = DOMPurify.sanitize(raw);",
	}, "\n")
	fs := []rules.Finding{finding(2, "79", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("DOMPurify.sanitize should suppress CWE-79, kept %v", keptLines(got))
	}
}

func TestJsFilter_XSS_ResJSON_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const v = req.query.v;",
		"res.json({ value: v });",
	}, "\n")
	fs := []rules.Finding{finding(2, "79", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("res.json should suppress CWE-79, kept %v", keptLines(got))
	}
}

func TestJsFilter_Cmdi_ExecFile_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const name = req.query.name;",
		"execFile('ls', [name]);",
	}, "\n")
	fs := []rules.Finding{finding(2, "78", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("execFile should suppress CWE-78, kept %v", keptLines(got))
	}
}

func TestJsFilter_Cmdi_TypeCoercion_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const n = parseInt(req.query.n, 10);",
		"exec('sleep ' + n);",
	}, "\n")
	fs := []rules.Finding{finding(2, "78", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("parseInt coercion should suppress CWE-78, kept %v", keptLines(got))
	}
}

func TestJsFilter_PathTraversal_Basename_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const f = path.basename(req.query.f);",
		"fs.readFile('/data/' + f, cb);",
	}, "\n")
	fs := []rules.Finding{finding(2, "22", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("path.basename should suppress CWE-22, kept %v", keptLines(got))
	}
}

func TestJsFilter_PathTraversal_ResolveAndStartsWith_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const p = path.resolve(BASE, req.query.f);",
		"if (!p.startsWith(BASE)) throw new Error('bad');",
		"fs.readFile(p, cb);",
	}, "\n")
	fs := []rules.Finding{finding(3, "22", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("path.resolve+startsWith should suppress CWE-22, kept %v", keptLines(got))
	}
}

func TestJsFilter_SSRF_ValidatorIsURL_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const url = req.query.url;",
		"if (validator.isURL(url)) {",
		"  fetch(url);",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(3, "918", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("validator.isURL should suppress CWE-918, kept %v", keptLines(got))
	}
}

func TestJsFilter_SSRF_URLParseAndHostnameCheck_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const u = new URL(req.query.url);",
		"if (u.hostname === 'api.example.com') {",
		"  fetch(u);",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(3, "918", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("new URL + hostname check should suppress CWE-918, kept %v", keptLines(got))
	}
}

func TestJsFilter_NoSQL_MongoSanitize_Suppressed(t *testing.T) {
	// jsMongoSanitize matches the library name token "mongo-sanitize".
	content := strings.Join([]string{
		"const sanitize = require('mongo-sanitize');",
		"User.find(sanitize(req.body));",
	}, "\n")
	fs := []rules.Finding{finding(2, "943", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("mongo-sanitize should suppress CWE-943, kept %v", keptLines(got))
	}
}

func TestJsFilter_Deser_JSONParse_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const obj = JSON.parse(req.body.data);",
		"process(obj);",
	}, "\n")
	fs := []rules.Finding{finding(1, "502", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("JSON.parse should suppress CWE-502, kept %v", keptLines(got))
	}
}

func TestJsFilter_SSTI_ResRender_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const name = req.query.name;",
		"res.render('profile', { name });",
	}, "\n")
	fs := []rules.Finding{finding(2, "1336", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("res.render static template should suppress CWE-1336, kept %v", keptLines(got))
	}
}

func TestJsFilter_Redirect_RelativePathGuard_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"const target = req.query.next;",
		"if (target.startsWith('http')) target = '/';",
		"res.redirect(target);",
	}, "\n")
	fs := []rules.Finding{finding(3, "601", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("relative-path guard should suppress CWE-601, kept %v", keptLines(got))
	}
}

func TestJsFilter_UnknownCWE_NotSuppressed(t *testing.T) {
	// A CWE without a suppression case (e.g. CWE-611 XXE) flows through.
	content := strings.Join([]string{
		"const x = req.query.x;",
		"parser.parseFromString(x);",
	}, "\n")
	fs := []rules.Finding{finding(2, "611", "BATOU-TAINT")}
	got := jsFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Errorf("unhandled CWE should be kept, kept %v", keptLines(got))
	}
}

// =========================================================================
// Go filter — goFilterTaintFindings
// =========================================================================

func TestGoFilter_XSSWithJSONContentType_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		`	w.Header().Set("Content-Type", "application/json")`,
		"	name := r.URL.Query().Get(\"name\")",
		"	w.Write([]byte(name))",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(4, "79", "BATOU-TAINT")}
	got := goFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("JSON Content-Type should suppress CWE-79, kept %v", keptLines(got))
	}
}

func TestGoFilter_XSSWithoutJSONContentType_Kept(t *testing.T) {
	content := strings.Join([]string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		"	name := r.URL.Query().Get(\"name\")",
		"	w.Write([]byte(\"<h1>\" + name + \"</h1>\"))",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(3, "79", "BATOU-TAINT")}
	got := goFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Errorf("XSS without JSON content-type should be kept, kept %v", keptLines(got))
	}
}

func TestGoFilter_NonXSSWithJSONContentType_Kept(t *testing.T) {
	// The JSON content-type suppression is CWE-79 only; a SQLi (CWE-89)
	// finding in the same file must still be kept.
	content := strings.Join([]string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		`	w.Header().Set("Content-Type", "application/json")`,
		"	id := r.URL.Query().Get(\"id\")",
		"	db.Query(\"SELECT * FROM t WHERE id = \" + id)",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(4, "89", "BATOU-TAINT")}
	got := goFilterTaintFindings(content, fs)
	if len(got) != 1 {
		t.Errorf("non-XSS finding should survive JSON content-type pre-scan, kept %v", keptLines(got))
	}
}

func TestGoFilter_TextPlainContentType_Suppressed(t *testing.T) {
	content := strings.Join([]string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		`	w.Header().Set("Content-Type", "text/plain")`,
		"	name := r.URL.Query().Get(\"name\")",
		"	w.Write([]byte(name))",
		"}",
	}, "\n")
	fs := []rules.Finding{finding(4, "79", "BATOU-TAINT")}
	got := goFilterTaintFindings(content, fs)
	if len(got) != 0 {
		t.Errorf("text/plain Content-Type should suppress CWE-79, kept %v", keptLines(got))
	}
}

// =========================================================================
// Helper predicates exercised directly
// =========================================================================

func TestJsHasTypeCoercionNearby(t *testing.T) {
	lines := []string{
		"const a = 1;",
		"const n = Number(req.query.n);",
		"doThing(n);",
	}
	if !jsHasTypeCoercionNearby(lines, 2) {
		t.Error("expected type coercion detected for Number()")
	}
	clean := []string{"const a = req.query.a;", "doThing(a);"}
	if jsHasTypeCoercionNearby(clean, 1) {
		t.Error("did not expect type coercion in clean code")
	}
}

func TestJsHasAllowlistNearby(t *testing.T) {
	lines := []string{
		"const ALLOWED = ['a', 'b'];",
		"if (ALLOWED.includes(x)) {",
		"  use(x);",
		"}",
	}
	if !jsHasAllowlistNearby(lines, 2) {
		t.Error("expected allowlist detected for ALLOWED.includes")
	}
	mapLines := []string{
		"const v = ENUM_MAP[key];",
		"use(v);",
	}
	if !jsHasAllowlistNearby(mapLines, 1) {
		t.Error("expected map-lookup detected for ENUM_MAP[key]")
	}
}

func TestJsHasRegexGuardNearby(t *testing.T) {
	lines := []string{
		"if (/^[a-z]+$/.test(x)) {",
		"  use(x);",
		"}",
	}
	if !jsHasRegexGuardNearby(lines, 1) {
		t.Error("expected regex guard detected for .test()")
	}
}
