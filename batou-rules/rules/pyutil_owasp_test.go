package rules

import (
	"strings"
	"testing"
)

// owaspXSSCases verifies PyLastAssignmentIsSafe / PySinkVarIsSafe handle the
// OWASP Python benchmark XSS idioms — both vulnerable cases (must return
// false / NOT safe) and safe-by-OWASP-classification cases (must return
// true / safe).
func TestPySinkVarIsSafe_OWASPXSSIdioms(t *testing.T) {
	t.Helper()
	tests := []struct {
		name string
		src  string
		// wantSafe true means PySinkVarIsSafe must return true at the sink line.
		wantSafe bool
	}{
		{
			name: "values-getlist-conditional-tainted",
			src: `def f():
	values = request.form.getlist("X")
	param = ""
	if values:
		param = values[0]
	bar = "safe" if (7*42) - num > 200 else param
	RESPONSE += f'Parameter value: {bar}'`,
			wantSafe: false,
		},
		{
			name: "request-path-via-parts-safe",
			src: `def f():
	parts = request.path.split("/")
	param = parts[1]
	if not param:
		param = ""
	bar = ''
	if param:
		bar = param.split(' ')[0]
	RESPONSE += f'Parameter value: {bar}'`,
			wantSafe: true,
		},
		{
			name: "param-direct-form-get",
			src: `def f():
	param = request.form.get("X")
	if not param:
		param = ""
	bar = ''
	if param:
		bar = param.split(' ')[0]
	RESPONSE += f'Parameter value: {bar}'`,
			wantSafe: false,
		},
		{
			name: "base64-roundtrip-tainted-param",
			src: `def f():
	param = request.form.get("X")
	if not param:
		param = ""
	import base64
	tmp = base64.b64encode(param.encode('utf-8'))
	bar = base64.b64decode(tmp).decode('utf-8')
	RESPONSE += f'bar is {bar}'`,
			wantSafe: false,
		},
		{
			name: "dict-map-tainted-key-via-format",
			src: `def f():
	param = request.form.get("X")
	if not param:
		param = ""
	dict = {}
	dict['bar'] = param
	dict['otherarg'] = 'this is it'
	RESPONSE += ('bar is \'{0[bar]}\' and otherarg is \'{0[otherarg]}\''.format(dict))`,
			wantSafe: false,
		},
		{
			name: "dict-map-safe-key-via-format",
			src: `def f():
	param = request.form.get("X")
	if not param:
		param = ""
	map1 = {}
	map1['keyA'] = 'a-Value'
	map1['keyB'] = param
	map1['keyC'] = 'another-Value'
	bar = map1['keyA']
	RESPONSE += f'Parameter value: {bar}'`,
			wantSafe: true,
		},
		// 00364 (OWASP-safe): escape_for_html(param) → dict['bar'] = bar.
		// PySinkVarIsSafe returns false (chain reaches a tainted source),
		// but XSS-013's own lineEscaped check suppresses the finding when
		// an escape call is within the lookback window.
		{
			name: "escape-for-html-via-dict-bar-chain-tainted",
			src: `def f():
	param = ""
	for name in request.form.keys():
		if "X" in request.form.getlist(name):
			param = name
			break
	bar = helpers.utils.escape_for_html(param)
	dict = {}
	dict['bar'] = bar
	dict['otherarg'] = 'this is it'
	RESPONSE += ('bar is \'{0[bar]}\' and otherarg is \'{0[otherarg]}\''.format(dict))`,
			wantSafe: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.src, "\n")
			// Find the sink line (last RESPONSE += line).
			sinkIdx := -1
			for i, l := range lines {
				if strings.Contains(l, "RESPONSE +=") {
					sinkIdx = i
				}
			}
			if sinkIdx < 0 {
				t.Fatal("no sink line found")
			}
			got := PySinkVarIsSafe(lines, sinkIdx)
			if got != tc.wantSafe {
				t.Errorf("PySinkVarIsSafe = %v, want %v", got, tc.wantSafe)
				for i, l := range lines {
					t.Logf("  %2d: %s", i, l)
				}
			}
		})
	}
}

// TestPyLastAssignmentIsSafe_TrustboundIdioms locks in the OWASP Python
// trustbound (CWE-501) FP fixes: a sink variable assigned in an if/else or
// match arm where every branch resolves to a safe origin (get_safe_value
// sanitizer, or request.path-only via ConfigParser/dict indirection) must be
// reported safe — while the structurally identical true-positive case
// (else-branch sourced from request.cookies, or a bare tainted config value)
// must remain unsafe.
func TestPyLastAssignmentIsSafe_TrustboundIdioms(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		wantSafe bool
	}{
		{
			// An unknown helper return (scr.get_safe_value here, but any
			// unrecognised method) provides no evidence of safety — the
			// origin is unresolvable, so the value must stay potentially
			// tainted. get_safe_value was previously special-cased as a
			// known sanitizer; it is an OWASP Benchmark helper that exists
			// nowhere else, and benchmark-specific names must not appear in
			// detection logic.
			name: "ifelse-unknown-helper-not-provably-safe",
			src: `def f():
	scr = helpers.separate_request.request_wrapper(request)
	param = scr.get_safe_value("X")
	TestParam = "This should never happen"
	if 'should' not in TestParam:
		bar = "Ifnot case passed"
	else:
		bar = param
	flask.session[bar] = '12345'`,
			wantSafe: false,
		},
		{
			// BenchmarkTest00072 (TRUE POSITIVE): identical structure but param
			// is sourced from request.cookies — must stay unsafe.
			name: "ifelse-request-cookies-tainted",
			src: `def f():
	param = urllib.parse.unquote_plus(request.cookies.get("X", "none"))
	TestParam = "This should never happen"
	if 'should' not in TestParam:
		bar = "Ifnot case passed"
	else:
		bar = param
	flask.session[bar] = '12345'`,
			wantSafe: false,
		},
		{
			// BenchmarkTest01092: ConfigParser key set to param <- parts[1] <-
			// request.path.split("/"); request.path is benchmark-safe.
			name: "config-keyB-request-path-safe",
			src: `def f():
	parts = request.path.split("/")
	param = parts[1]
	if not param:
		param = ""
	bar = 'safe!'
	conf = configparser.ConfigParser()
	conf.add_section('s')
	conf.set('s', 'keyA', 'a-Value')
	conf.set('s', 'keyB', param)
	bar = conf.get('s', 'keyB')
	flask.session[bar] = '12345'`,
			wantSafe: true,
		},
		{
			// PY021 analogue (TRUE POSITIVE): ConfigParser key set to a bare,
			// unresolved tainted `param` — must stay unsafe.
			name: "config-keyB-bare-param-tainted",
			src: `def f(param):
	conf = configparser.ConfigParser()
	conf.add_section('s')
	conf.set('s', 'keyA', 'a-Value')
	conf.set('s', 'keyB', param)
	bar = conf.get('s', 'keyB')
	flask.session[bar] = '12345'`,
			wantSafe: false,
		},
		{
			// BenchmarkTest01093: match/case where every case resolves safe
			// (literal or param<-request.path).
			name: "match-case-all-safe",
			src: `def f():
	parts = request.path.split("/")
	param = parts[1]
	if not param:
		param = ""
	guess = "ABC"[0]
	match guess:
		case 'A':
			bar = param
		case 'B':
			bar = 'bob'
		case _:
			bar = 'literal'
	flask.session[bar] = '12345'`,
			wantSafe: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.src, "\n")
			sinkIdx := -1
			for i, l := range lines {
				if strings.Contains(l, "flask.session[bar]") {
					sinkIdx = i
				}
			}
			if sinkIdx < 0 {
				t.Fatal("no sink line found")
			}
			got := PyLastAssignmentIsSafe(lines, sinkIdx, "bar")
			if got != tc.wantSafe {
				t.Errorf("PyLastAssignmentIsSafe = %v, want %v", got, tc.wantSafe)
				for i, l := range lines {
					t.Logf("  %2d: %s", i, l)
				}
			}
		})
	}
}

// TestPyHasContainmentGuard verifies the variable-scoped containment guard
// detector (pyast-fpr): membership (`p in ALLOWED` / `p not in DENY`) and
// prefix (`p.startswith(BASE)`) checks on the named variable return true, while
// a guard on an unrelated variable returns false.
func TestPyHasContainmentGuard(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		varName string
		sinkSub string
		want    bool
	}{
		{
			name: "in-allowlist",
			src: `p = request.args.get('f')
if p in ALLOWED:
    open(p)`,
			varName: "p", sinkSub: "open(p)", want: true,
		},
		{
			name: "not-in-denylist",
			src: `p = request.args.get('f')
if p not in ALLOWED:
    return
open(p)`,
			varName: "p", sinkSub: "open(p)", want: true,
		},
		{
			name: "startswith-prefix",
			src: `p = request.args.get('f')
if p.startswith(BASE):
    open(p)`,
			varName: "p", sinkSub: "open(p)", want: true,
		},
		{
			name: "str-wrapped-startswith",
			src: `p = request.args.get('f')
if str(p).startswith(str(BASE)):
    open(p)`,
			varName: "p", sinkSub: "open(p)", want: true,
		},
		{
			name: "guard-on-other-var",
			src: `q = request.args.get('q')
p = request.args.get('f')
if q in ALLOWED:
    pass
open(p)`,
			varName: "p", sinkSub: "open(p)", want: false,
		},
		{
			name: "no-guard",
			src: `p = request.args.get('f')
open(p)`,
			varName: "p", sinkSub: "open(p)", want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lines := strings.Split(tc.src, "\n")
			sinkIdx := -1
			for i, l := range lines {
				if strings.Contains(l, tc.sinkSub) {
					sinkIdx = i
				}
			}
			if sinkIdx < 0 {
				t.Fatalf("sink line %q not found", tc.sinkSub)
			}
			if got := PyHasContainmentGuard(lines, sinkIdx, tc.varName); got != tc.want {
				t.Errorf("PyHasContainmentGuard(%q) = %v, want %v", tc.varName, got, tc.want)
			}
		})
	}
}
