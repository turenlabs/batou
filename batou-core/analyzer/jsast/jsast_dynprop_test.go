package jsast

import "testing"

// hasJSRule reports whether the AST analyzer emits a finding with the given
// rule ID for the supplied JS source.
func hasJSRule(code, ruleID string) bool {
	for _, f := range scanJS(code) {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// --- BATOU-JSAST-007: prototype-polluting computed-key assignment ---

func TestProtoPollutingAssign_Fires(t *testing.T) {
	tps := []string{
		// classic copy-loop over req.body keys
		`function f(req){ const dst = {}; for (const k in req.body) { dst[k] = req.body[k]; } }`,
		// direct request-derived key
		`function f(req){ obj[req.query.field] = val; }`,
		// member base + request key
		`function f(req){ this.cfg[req.params.key] = req.params.value; }`,
		// for-in over request.query (alternate root)
		`function f(request){ for (const k in request.query) { target[k] = request.query[k]; } }`,
		// koa-style ctx.body container segment
		`function f(ctx){ opts[ctx.body.name] = 1; }`,
		// request container appearing as a chain segment under a non-request root
		`function f(data){ store[data.body.field] = 2; }`,
	}
	for _, c := range tps {
		if !hasJSRule(c, "BATOU-JSAST-007") {
			t.Errorf("expected BATOU-JSAST-007 to fire on: %s", c)
		}
	}
}

func TestProtoPollutingAssign_NoFP(t *testing.T) {
	fps := []string{
		// literal / constant keys — the dominant safe shape
		`function f(){ obj.fixed = x; }`,
		`function f(){ obj["const"] = y; }`,
		// numeric-index array writes from a counter loop
		`function f(){ const arr = []; for (let i = 0; i < n; i++) { arr[i] = data[i]; } }`,
		// plain function-parameter key (not request-derived)
		`function f(map, k){ map[k] = v; }`,
		// for-in over a NON-request object
		`function f(){ for (const k in config) { dst[k] = config[k]; } }`,
		// hashed/derived key, not request input
		`function f(){ cache[hash] = result; }`,
		// `context` is a generic/typed handler param, NOT an HTTP request root —
		// must not be treated as request-tainted (real n8n rbac.store shape).
		`function f(context){ scopesById[context.projectId] = []; }`,
		// `ctx` alone (no request segment) is likewise too generic.
		`function f(ctx){ store[ctx.id] = v; }`,
	}
	for _, c := range fps {
		if hasJSRule(c, "BATOU-JSAST-007") {
			t.Errorf("BATOU-JSAST-007 false positive on: %s", c)
		}
	}
}

// --- BATOU-JSAST-008: unsafe dynamic method dispatch ---

func TestDynamicDispatch_Fires(t *testing.T) {
	tps := []string{
		`function f(req){ handlers[req.body.action](payload); }`,
		`function f(req){ table[req.query.cmd](a, b); }`,
		`function f(req){ for (const k in req.body) { api[k](req.body[k]); } }`,
	}
	for _, c := range tps {
		if !hasJSRule(c, "BATOU-JSAST-008") {
			t.Errorf("expected BATOU-JSAST-008 to fire on: %s", c)
		}
	}
}

func TestDynamicDispatch_NoFP(t *testing.T) {
	fps := []string{
		// constant-string selector dispatch table
		`function f(){ obj["fixed"](); }`,
		// normal dotted method call
		`function f(){ handlers.action(payload); }`,
		// array element call from a numeric index
		`function f(arr, i){ arr[i](); }`,
		// for-in over a NON-request object
		`function f(){ for (const k in opts) { fns[k](); } }`,
	}
	for _, c := range fps {
		if hasJSRule(c, "BATOU-JSAST-008") {
			t.Errorf("BATOU-JSAST-008 false positive on: %s", c)
		}
	}
}
