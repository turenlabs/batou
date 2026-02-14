package prototype

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// --- GTSS-PROTO-001: Prototype Pollution via Merge/Extend ---

func TestPROTO001_LodashMerge(t *testing.T) {
	content := `const userInput = req.body;
_.merge(config, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-001")
}

func TestPROTO001_DeepMerge(t *testing.T) {
	content := `const data = req.body;
deepmerge(target, req.body);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-001")
}

func TestPROTO001_DefaultsDeep(t *testing.T) {
	content := `const opts = req.body;
_.defaultsDeep(defaults, req.body);`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-001")
}

func TestPROTO001_ObjectAssign(t *testing.T) {
	content := `const body = req.body;
Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-001")
}

func TestPROTO001_SpreadOperator(t *testing.T) {
	content := `const updated = {...user, ...req.body};`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-001")
}

func TestPROTO001_Safe_Sanitized(t *testing.T) {
	content := `const sanitized = sanitize(req.body);
_.merge(config, sanitized);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-PROTO-001")
}

func TestPROTO001_Safe_NoUserInput(t *testing.T) {
	content := `const defaults = { timeout: 5000 };
_.merge(config, defaults);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-PROTO-001")
}

// --- GTSS-PROTO-002: Direct __proto__ Assignment ---

func TestPROTO002_BracketProto(t *testing.T) {
	content := `obj["__proto__"] = maliciousPayload;`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-002")
}

func TestPROTO002_DirectProtoAssign(t *testing.T) {
	content := `target.__proto__ = attackerObj;`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-002")
}

func TestPROTO002_ConstructorPrototype(t *testing.T) {
	content := `obj.constructor.prototype.isAdmin = true;`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-002")
}

func TestPROTO002_DynamicPropUserInput(t *testing.T) {
	content := `const key = req.body.key;
obj[key] = value;`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-PROTO-002")
}

func TestPROTO002_Safe_DefensiveCheck(t *testing.T) {
	// Defensive check should not trigger
	content := `if (key === "__proto__") { return; }`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-PROTO-002")
}

func TestPROTO002_Safe_DeleteProto(t *testing.T) {
	content := `delete obj["__proto__"];`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-PROTO-002")
}
