package prototype

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// --- BATOU-PROTO-001: Prototype Pollution via Merge/Extend ---

func TestPROTO001_LodashMerge(t *testing.T) {
	content := `const userInput = req.body;
_.merge(config, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-PROTO-001", "BATOU-PROTO-003")
}

func TestPROTO001_DeepMerge(t *testing.T) {
	content := `const data = req.body;
deepmerge(target, req.body);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-001")
}

func TestPROTO001_DefaultsDeep(t *testing.T) {
	content := `const opts = req.body;
_.defaultsDeep(defaults, req.body);`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-001")
}

func TestPROTO001_ObjectAssign(t *testing.T) {
	content := `const body = req.body;
Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-PROTO-001", "BATOU-PROTO-003")
}

func TestPROTO001_SpreadOperator(t *testing.T) {
	content := `const updated = {...user, ...req.body};`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-001")
}

func TestPROTO001_Safe_Sanitized(t *testing.T) {
	content := `const sanitized = sanitize(req.body);
_.merge(config, sanitized);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-001")
}

func TestPROTO001_Safe_NoUserInput(t *testing.T) {
	content := `const defaults = { timeout: 5000 };
_.merge(config, defaults);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-001")
}

// --- BATOU-PROTO-002: Direct __proto__ Assignment ---

func TestPROTO002_BracketProto(t *testing.T) {
	content := `obj["__proto__"] = maliciousPayload;`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-002")
}

func TestPROTO002_DirectProtoAssign(t *testing.T) {
	content := `target.__proto__ = attackerObj;`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-PROTO-002", "BATOU-PROTO-007")
}

func TestPROTO002_ConstructorPrototype(t *testing.T) {
	content := `obj.constructor.prototype.isAdmin = true;`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-002")
}

func TestPROTO002_DynamicPropUserInput(t *testing.T) {
	content := `const key = req.body.key;
obj[key] = value;`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-002")
}

func TestPROTO002_Safe_DefensiveCheck(t *testing.T) {
	// Defensive check should not trigger
	content := `if (key === "__proto__") { return; }`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-002")
}

func TestPROTO002_Safe_DeleteProto(t *testing.T) {
	content := `delete obj["__proto__"];`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-002")
}

// --- BATOU-PROTO-009: Lodash sinks with import evidence (variable args) ---
// These fixtures mirror the CVE-2019-10744 / CVE-2020-8203 / CVE-2018-16487
// shapes: a route handler that takes a request body and passes it through
// a variable into a lodash prototype-pollution sink. Older rules required
// the user-input literal on the same line and missed the variable-indirection
// shape, so BATOU-PROTO-009 fires on the sink as long as lodash is imported.

func TestPROTO009_DefaultsDeep_Variable(t *testing.T) {
	content := `const _ = require("lodash");
app.post("/preferences", function (req, res) {
  const userPrefs = req.body;
  const defaults = { theme: "light" };
  const merged = _.defaultsDeep(defaults, userPrefs);
  res.json(merged);
});`
	result := testutil.ScanContent(t, "/app/preferences.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-009")
}

func TestPROTO009_Set_Variable(t *testing.T) {
	content := `const _ = require("lodash");
app.post("/field", function (req, res) {
  const fieldPath = req.body.path;
  const value = req.body.value;
  _.set(config, fieldPath, value);
  res.json({ ok: true });
});`
	result := testutil.ScanContent(t, "/app/field.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-009")
}

func TestPROTO009_LodashNamespace(t *testing.T) {
	content := `const lodash = require("lodash");
function apply(req) {
  const merged = lodash.merge({}, req.body);
  return merged;
}`
	result := testutil.ScanContent(t, "/app/apply.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-009")
}

func TestPROTO009_Safe_NoLodashImport(t *testing.T) {
	// Without a lodash import in the file, BATOU-PROTO-009 stays quiet to
	// avoid false-positives on unrelated `_.merge`-like helpers.
	content := `function apply(target) {
  return _.merge(target, somethingElse);
}`
	result := testutil.ScanContent(t, "/app/apply.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-009")
}

func TestPROTO009_Safe_AllLiteralArgs(t *testing.T) {
	// All args are string-literals — known safe shape (e.g. config seeding).
	content := `const _ = require("lodash");
const config = {};
_.set(config, "theme", "light");`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-009")
}

// --- BATOU-PROTO-010: Hoek sinks with import evidence ---

func TestPROTO010_HoekMerge_Variable(t *testing.T) {
	content := `const Hoek = require("hoek");
app.put("/config", function (req, res) {
  const incoming = req.body;
  const merged = Hoek.merge({ theme: "light" }, incoming);
  res.json(merged);
});`
	result := testutil.ScanContent(t, "/app/config.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-010")
}

func TestPROTO010_HoekApplyToDefaults_Variable(t *testing.T) {
	content := `const Hoek = require("@hapi/hoek");
function setDefaults(req) {
  return Hoek.applyToDefaults({ theme: "light" }, req.body);
}`
	result := testutil.ScanContent(t, "/app/defaults.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-010")
}

func TestPROTO010_Safe_NoHoekImport(t *testing.T) {
	content := `function merge(a, b) { return Hoek.merge(a, b); }`
	result := testutil.ScanContent(t, "/app/m.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-010")
}

// --- BATOU-PROTO-011: Handlebars.compile / _.template with non-literal src ---

func TestPROTO011_Handlebars_Variable(t *testing.T) {
	content := `const Handlebars = require("handlebars");
app.post("/render", function (req, res) {
  const source = req.body.template;
  const tmpl = Handlebars.compile(source);
  res.send(tmpl({ name: "world" }));
});`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-011")
}

func TestPROTO011_LodashTemplate_Variable(t *testing.T) {
	content := `const _ = require("lodash");
app.post("/render", function (req, res) {
  const tmpl = req.body.template;
  const compiled = _.template(tmpl);
  res.send(compiled(req.body.data || {}));
});`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-011")
}

func TestPROTO011_Safe_StringLiteralSource(t *testing.T) {
	// Compiling from a string literal is the safe pattern (precompiled
	// trusted template). Must NOT fire.
	content := `const Handlebars = require("handlebars");
const templates = {
  greeting: Handlebars.compile("Hello, {{name}}!"),
};`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-011")
}

func TestPROTO011_Safe_LodashTemplateLiteralSource(t *testing.T) {
	content := `const _ = require("lodash");
const templates = {
  greeting: _.template("Hello, <%= name %>!"),
};`
	result := testutil.ScanContent(t, "/app/render.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-011")
}

// ---------------------------------------------------------------------------
// PR-CATjs-2: Fresh-destination suppression
// ---------------------------------------------------------------------------
// The primary suppression lives in the taint tier (tsflow walker) — those
// tests live in batou-core/taint/tsflow/tsflow_js_proto_pollution_test.go.
// The regex tier's BATOU-PROTO-003 was already gated by the arg-shape it
// matches (`Object.assign(\s*\w+\s*,\s*(?:req\.body|...)`), so the canonical
// fresh-dest shapes below are naturally not regex hits either. These tests
// pin that behaviour so a future regex widening doesn't reintroduce the
// FPs.

// `Object.assign({}, req.body)` — arg 0 is the `{}` literal so the
// BATOU-PROTO-003 regex (which requires `\w+` as arg 0) doesn't match.
func TestPROTO003_FreshDest_ObjectLiteral(t *testing.T) {
	content := `app.post("/echo", (req, res) => {
  const out = Object.assign({}, req.body);
  res.json(out);
});`
	result := testutil.ScanContent(t, "/app/echo.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-003")
}

// `Object.assign({}, data, { secret })` — Ghost-style shape with `{}`
// literal arg 0.
func TestPROTO003_FreshDest_GhostShape(t *testing.T) {
	content := `function buildPayload(data, secret) {
  return Object.assign({}, data, { secret });
}`
	result := testutil.ScanContent(t, "/app/ghost.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-003")
}

// `_.defaultsDeep(query, queryDefaults)` where `query` was declared as
// `{}`. The regex tier doesn't fire because `queryDefaults` isn't on the
// user-input source list. The taint tier's freshLocalEmpty bookkeeping
// suppresses the equivalent flow (covered in tsflow tests).
func TestPROTO004_FreshDest_LodashDefaultsDeep(t *testing.T) {
	content := `function processQuery(req) {
  const query = {};
  _.defaultsDeep(query, queryDefaults);
  return query;
}`
	result := testutil.ScanContent(t, "/app/lodash.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-PROTO-004")
}

// `_.set(obj, path, value)` with a user-controlled path on a freshly
// declared local — CVE-2020-8203 lives in this exact shape (path
// traversal via `__proto__.x`). The fresh-dest suppression deliberately
// does NOT cover _.set / _.setWith / _.zipObjectDeep, so BATOU-PROTO-009
// must still fire.
func TestPROTO004_FreshDest_LodashSetStillFlagged(t *testing.T) {
	content := `const _ = require("lodash");
app.post("/path-set", function setField(req, res) {
  const obj = {};
  const path = req.body.path;
  _.set(obj, path, "value");
});`
	result := testutil.ScanContent(t, "/app/setfresh.js", content)
	testutil.MustFindRule(t, result, "BATOU-PROTO-009")
}
