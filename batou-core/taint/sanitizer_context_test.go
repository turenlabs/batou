package taint_test

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// sanitizer_context_test.go guards against over-broad `Neutralizes` lists in
// sanitizer catalogs. A sanitizer that claims to clear taint for a sink
// category it does not actually protect will silently create false negatives
// (the worst failure mode for a SAST engine).
//
// Each case pairs a real sanitizer with a sink category it must NOT clear.
// The test fails if the engine reports zero flows — meaning the sanitizer
// has been miscategorized as safe for that context.
//
// When a legitimate sanitizer/sink pair belongs together, add it to the
// "expected-safe" section below instead of removing the assertion.

type contextCase struct {
	name           string
	lang           rules.Language
	file           string
	code           string
	mustHaveFlow   bool // true: flow must exist (context mismatch guard)
	mustHaveReason string
}

// ---------------------------------------------------------------------------
// Validators (Pydantic / marshmallow / wtforms / cerberus / php filter_var)
// are *type/shape* checkers. They do NOT escape SQL, shell metacharacters,
// or command injection payloads. Their Neutralizes lists currently claim
// otherwise — these cases pin the correct boundary.
// ---------------------------------------------------------------------------

var contextMismatchCases = []contextCase{
	{
		name: "pydantic parse does NOT sanitize SQL injection",
		lang: rules.LangPython,
		file: "pydantic_sql.py",
		code: `def handler(request):
    data = PydanticModel.parse_obj(request.json)
    cursor.execute("SELECT * FROM users WHERE name = '" + data + "'")
`,
		mustHaveFlow:   true,
		mustHaveReason: "pydantic validates types; SQL metacharacters still reach cursor.execute",
	},
	{
		name: "pydantic model_validate does NOT sanitize shell injection",
		lang: rules.LangPython,
		file: "pydantic_cmd.py",
		code: `def handler(request):
    data = PydanticModel.model_validate(request.json)
    os.system("echo " + data)
`,
		mustHaveFlow:   true,
		mustHaveReason: "pydantic does not escape shell metacharacters",
	},
	{
		name: "marshmallow Schema.load does NOT sanitize SQL injection",
		lang: rules.LangPython,
		file: "marshmallow_sql.py",
		code: `def handler(request):
    data = schema.load(request.json)
    cursor.execute("SELECT * FROM users WHERE name = '" + data + "'")
`,
		mustHaveFlow:   true,
		mustHaveReason: "marshmallow validates schema, not SQL safety",
	},
	{
		name: "wtforms validate does NOT sanitize shell injection",
		lang: rules.LangPython,
		file: "wtforms_cmd.py",
		code: `def handler(request):
    raw = request.form['x']
    ok = form.validate_on_submit()
    value = raw
    os.system("ls " + value)
`,
		mustHaveFlow:   true,
		mustHaveReason: "wtforms checks field validity, does not escape shell chars",
	},
	{
		name: "cerberus validate does NOT sanitize SQL injection",
		lang: rules.LangPython,
		file: "cerberus_sql.py",
		code: `def handler(request):
    v = Validator(schema).validate(request.json)
    cursor.execute("SELECT * FROM t WHERE x='" + v + "'")
`,
		mustHaveFlow:   true,
		mustHaveReason: "cerberus validates schema shape, not SQL metacharacters",
	},
	{
		name: "php filter_var does NOT universally sanitize SQL injection",
		lang: rules.LangPHP,
		file: "filter_var_sql.php",
		code: `<?php
function h($req) {
    $clean = filter_var($_GET['name'], FILTER_VALIDATE_EMAIL);
    mysqli_query($conn, "SELECT * FROM u WHERE e='" . $clean . "'");
}
`,
		mustHaveFlow:   true,
		mustHaveReason: "FILTER_VALIDATE_EMAIL doesn't escape SQL quote chars",
	},
	{
		name: "php filter_input (no sanitize flag) does NOT sanitize shell injection",
		lang: rules.LangPHP,
		file: "filter_input_cmd.php",
		code: `<?php
function h() {
    $raw = $_GET['cmd'];
    $val = filter_input(INPUT_GET, 'cmd');
    system("ls " . $raw . $val);
}
`,
		mustHaveFlow:   true,
		mustHaveReason: "filter_input without a FILTER_SANITIZE_* flag is a pass-through for $_GET taint",
	},
	// HTML escape consumed in JS/URL contexts — classic context confusion.
	{
		name: "html.escape output flowed to redirect is NOT safe",
		lang: rules.LangPython,
		file: "html_redirect.py",
		code: `def handler(request):
    raw = request.args.get("next")
    safe = html.escape(raw)
    return redirect(safe)
`,
		mustHaveFlow:   true,
		mustHaveReason: "HTML escape does not defend against open-redirect",
	},
}

func TestSanitizerContextMismatch(t *testing.T) {
	for _, c := range contextMismatchCases {
		t.Run(c.name, func(t *testing.T) {
			flows := taint.Analyze(c.code, c.file, c.lang)

			if c.mustHaveFlow && len(flows) == 0 {
				t.Errorf("context-mismatch bypass: %s — engine cleared taint but sanitizer should not cover this sink category", c.mustHaveReason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Positive guards: sanitizers that SHOULD legitimately clear taint for their
// actual protected categories. If these start failing, the engine's per-
// category sanitization machinery is broken.
// ---------------------------------------------------------------------------

var contextLegitCases = []contextCase{
	{
		name: "html.escape clears HTML output taint",
		lang: rules.LangPython,
		file: "html_ok.py",
		code: `def handler(request):
    raw = request.args.get("x")
    safe = html.escape(raw)
    return "<p>" + safe + "</p>"
`,
		mustHaveFlow:   false,
		mustHaveReason: "HTML escape is the correct defense for HTML output",
	},
	{
		name: "shlex.quote clears command taint",
		lang: rules.LangPython,
		file: "shlex_ok.py",
		code: `def handler(request):
    raw = request.args.get("x")
    safe = shlex.quote(raw)
    os.system("ls " + safe)
`,
		mustHaveFlow:   false,
		mustHaveReason: "shlex.quote is the canonical shell-metacharacter escaper",
	},
	{
		name: "int() cast clears SQL taint (numeric coercion)",
		lang: rules.LangPython,
		file: "int_ok.py",
		code: `def handler(request):
    raw = request.args.get("id")
    safe = int(raw)
    cursor.execute("SELECT * FROM t WHERE id=" + str(safe))
`,
		mustHaveFlow:   false,
		mustHaveReason: "integer coercion restricts input to digits",
	},
}

func TestSanitizerLegitimateClearance(t *testing.T) {
	for _, c := range contextLegitCases {
		t.Run(c.name, func(t *testing.T) {
			flows := taint.Analyze(c.code, c.file, c.lang)

			if !c.mustHaveFlow && len(flows) > 0 {
				t.Errorf("sanitizer not honored: %s — expected no flow, got %d. The per-category Sanitized map may be broken.", c.mustHaveReason, len(flows))
			}
		})
	}
}
