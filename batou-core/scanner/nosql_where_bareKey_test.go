package scanner_test

import (
	"testing"

	"github.com/turenlabs/batou-core/testutil"
	"github.com/turenlabs/batou-rules/rules"
)

// findCWE943 is a small local helper that works directly on the scan result's
// Findings slice (the reporter result type exposes Findings as a field).
func findCWE943(findings []rules.Finding) (rules.Finding, bool) {
	for _, f := range findings {
		if f.CWEID == "CWE-943" {
			return f, true
		}
	}
	return rules.Finding{}, false
}

// findRule returns the first finding with the given rule ID.
func findRule(findings []rules.Finding, ruleID string) (rules.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return rules.Finding{}, false
}

// TestNoSQLWhereBareKey_Vulnerable is the load-bearing test for the JavaScript
// MongoDB `$where` template-literal NoSQLi recall gap (NodeGoat
// allocations-dao.js): real Mongo/Node code uses the BARE JS object-key form
// `$where: ` + "`...${x}...`" + ` (no quotes around the key). The detection
// (BATOU-NOSQL-001, CWE-943) must fire on the bare-key template-literal and
// string-concat shapes, and must survive the JS FP filter even when an
// UNRELATED numeric coercion (parseInt on a different variable) sits nearby —
// the exact shape NodeGoat ships.
func TestNoSQLWhereBareKey_Vulnerable(t *testing.T) {
	cases := map[string]string{
		// NodeGoat allocations-dao.js shape: bare $where key, template literal,
		// a parseInt() on an UNRELATED variable (parsedUserId) nearby, and the
		// raw `threshold` parameter interpolated into the $where body.
		"bare key template + unrelated parseInt": `
function getByUserIdAndThreshold(userId, threshold, callback) {
    const parsedUserId = parseInt(userId);
    const searchCriteria = () => {
        if (threshold) {
            return {
                $where: ` + "`this.userId == ${parsedUserId} && this.stocks > '${threshold}'`" + `
            };
        }
    };
}
`,
		// Bare $where key, string concatenation of a request value.
		"bare key string concat": `
function handler(req) {
    const userInput = req.query.name;
    return db.collection.find({ $where: "this.name == '" + userInput + "'" });
}
`,
		// Single-quoted concat, bare key.
		"bare key single-quote concat": `
function handler(req) {
    return db.find({ $where: 'this.x == ' + req.body.x });
}
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			result := testutil.ScanContent(t, "allocations-dao.js", code)
			if _, ok := findCWE943(result.Findings); !ok {
				t.Errorf("expected a CWE-943 finding for %q, got none", name)
			}
		})
	}
}

// TestNoSQLWhereBareKey_Safe asserts the precise, sanitizer-aware negatives:
// static $where strings, hardcoded $where functions, a value coerced ON the
// $where line, and mongo-sanitize'd values must produce NO CWE-943 at all.
func TestNoSQLWhereBareKey_Safe(t *testing.T) {
	cases := map[string]string{
		// Static string body — no interpolation, no concat.
		"static string $where": `
function f() { return { $where: "this.active === true" }; }
`,
		// Hardcoded function — not a string built from user input.
		"hardcoded function $where": `
function f() { return { $where: function() { return this.x > 5; } }; }
`,
		// Arrow function body.
		"hardcoded arrow $where": `
function f() { return { $where: () => this.x > 5 }; }
`,
		// Numeric coercion of the interpolated value ON the $where line.
		"coerced value on $where line": `
function f(req) {
    const threshold = req.query.threshold;
    return { $where: ` + "`this.stocks > ${parseInt(threshold)}`" + ` };
}
`,
		// mongo-sanitize applied to the value.
		"mongo-sanitize present": `
const sanitize = require('mongo-sanitize');
function f(req) {
    const t = sanitize(req.query.t);
    return { $where: ` + "`this.stocks > '${t}'`" + ` };
}
`,
		// Static template literal (no ${} interpolation) — not injectable.
		"static template no interpolation": `
function f() { return { $where: ` + "`this.active === true`" + ` }; }
`,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			result := testutil.ScanContent(t, "dao.js", code)
			if f, ok := findCWE943(result.Findings); ok {
				t.Errorf("expected NO CWE-943 finding for %q, but got one: rule=%s line=%d text=%q",
					name, f.RuleID, f.LineNumber, f.MatchedText)
			}
		})
	}
}

// TestNoSQLWhereBareKey_FieldQueryNotWhere asserts the $where rule
// (BATOU-NOSQL-001) does NOT fire on a parameterized field-value query — a
// safe Mongo pattern that is NOT a $where clause. (A separate, pre-existing
// injection rule may flag req.* near a Mongo find(); that is out of scope for
// the $where lever — here we pin only that the $where rule stays silent.)
func TestNoSQLWhereBareKey_FieldQueryNotWhere(t *testing.T) {
	code := `
function f(req) { const id = req.query.id; return collection.find({ userId: id }); }
`
	result := testutil.ScanContent(t, "dao.js", code)
	if f, ok := findRule(result.Findings, "BATOU-NOSQL-001"); ok {
		t.Errorf("BATOU-NOSQL-001 ($where) must not fire on a field-value query: line=%d text=%q",
			f.LineNumber, f.MatchedText)
	}
}
