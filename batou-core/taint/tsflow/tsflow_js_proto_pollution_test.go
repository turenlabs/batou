package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ---------------------------------------------------------------------------
// Prototype pollution — SnkPrototype (CWE-1321)
// (Was SnkDeserialize prior to the BATOU-JSTS-PROTO-* sink reshuffle; the
// new category gives findings the correct CWE-1321 mapping.)
// ---------------------------------------------------------------------------

func TestJS_ProtoPollution_Lodash_Merge(t *testing.T) {
	// PR-CATjs-2: dest must be a non-fresh object for the merge-style
	// suppression to NOT apply. A const initialised from another call
	// (here `defaults()`) is treated as potentially-shared and still
	// flagged when a tainted source is merged in.
	code := `
const _ = require('lodash');

app.post('/config', (req, res) => {
    const input = req.body;
    const config = _.merge(target, input);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/config.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected prototype-pollution flow from req.body -> _.merge()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ProtoPollution_Lodash_DefaultsDeep(t *testing.T) {
	// PR-CATjs-2: non-fresh destination (function-parameter `defaults`)
	// keeps the sink flaggable.
	code := `
const _ = require('lodash');

function applyDefaults(defaults, req) {
    const user = req.body.settings;
    const merged = _.defaultsDeep(defaults, user);
    return merged;
}
`
	flows := Analyze(code, "/app/routes/settings.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected prototype-pollution flow from req.body.settings -> _.defaultsDeep()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ProtoPollution_Lodash_Set(t *testing.T) {
	code := `
const _ = require('lodash');

app.post('/update', (req, res) => {
    const path = req.body.path;
    const obj = {};
    _.set(obj, path, 'value');
    res.json(obj);
});
`
	flows := Analyze(code, "/app/routes/update.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected prototype-pollution flow from req.body.path -> _.set()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ProtoPollution_Lodash_ZipObjectDeep(t *testing.T) {
	code := `
const _ = require('lodash');

app.post('/zip', (req, res) => {
    const paths = req.body.paths;
    const obj = _.zipObjectDeep(paths, ['v1', 'v2']);
    res.json(obj);
});
`
	flows := Analyze(code, "/app/routes/zip.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected prototype-pollution flow from req.body.paths -> _.zipObjectDeep()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ProtoPollution_Hoek_Merge(t *testing.T) {
	// PR-CATjs-2: a function-parameter destination ("profile") is
	// unknown-origin and still gets flagged when a tainted source is
	// merged in.
	code := `
const Hoek = require('@hapi/hoek');

function applyProfile(profile, req) {
    const input = req.body;
    const merged = Hoek.merge(profile, input);
    return merged;
}
`
	flows := Analyze(code, "/app/routes/profile.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected prototype-pollution flow from req.body -> Hoek.merge()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_ProtoPollution_Hoek_ApplyToDefaults(t *testing.T) {
	code := `
const Hoek = require('@hapi/hoek');

app.post('/defaults', (req, res) => {
    const options = req.body.opts;
    const config = Hoek.applyToDefaults({ host: 'localhost' }, options);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/defaults.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected prototype-pollution flow from req.body.opts -> Hoek.applyToDefaults()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: merge with static config object — no taint source reaches the sink.
func TestJS_ProtoPollution_Lodash_Merge_Safe(t *testing.T) {
	code := `
const _ = require('lodash');

const defaults = { timeout: 30, retries: 3 };

app.get('/static', (req, res) => {
    const config = _.merge({}, defaults);
    res.json(config);
});
`
	flows := Analyze(code, "/app/routes/static.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("did not expect proto-pollution flow when input is static, not req-derived")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ---------------------------------------------------------------------------
// PR-CATjs-2: fresh-destination suppression
// ---------------------------------------------------------------------------

// Object.assign({}, req.body) — destination is a literal `{}`, can't reach
// Object.prototype, so the sink shouldn't fire.
func TestJS_ProtoPollution_FreshDest_ObjectAssign_Literal(t *testing.T) {
	code := `
app.post('/echo', (req, res) => {
    const out = Object.assign({}, req.body);
    res.json(out);
});
`
	flows := Analyze(code, "/app/routes/echo.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow when dest is a fresh `{}` literal")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Object.assign({}, data, { secret }) — Ghost shape.
func TestJS_ProtoPollution_FreshDest_ObjectAssign_GhostShape(t *testing.T) {
	code := `
function buildPayload(data, secret) {
    return Object.assign({}, data, { secret });
}
`
	flows := Analyze(code, "/app/routes/ghost.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow with `{}` dest and trailing object literal")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// const obj = {}; Object.assign(obj, req.body) — local const dest.
func TestJS_ProtoPollution_FreshDest_LocalConstEmpty(t *testing.T) {
	code := `
app.post('/echo', (req, res) => {
    const obj = {};
    Object.assign(obj, req.body);
    res.json(obj);
});
`
	flows := Analyze(code, "/app/routes/local.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow with local const `{}` dest")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Object.assign(req.body, defaults) — destination IS a function parameter
// (req.body originates from req which is a handler param). The dangerous
// arg is the SECOND arg (defaults) which is untainted, but we want to
// confirm the suppression only kicks in when dest is fresh — here dest
// is req.body, which is not fresh.
func TestJS_ProtoPollution_PollutedDest_ParamProperty(t *testing.T) {
	// The canonical attack shape: Object.assign(target, src) where src is
	// tainted and target is a param-derived value. We construct this so
	// the SOURCE is req.body and the destination is itself a param, so
	// fresh-suppression must NOT skip it.
	code := `
function applyDefaults(target, req) {
    const src = req.body;
    Object.assign(target, src);
}
`
	flows := Analyze(code, "/app/routes/polluted.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected proto-pollution flow when dest is a function-param value")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// _.defaultsDeep(query, queryDefaults) where `query` is freshly declared
// as `{}` in scope. The Ghost shape minus the cloneDeep — same conclusion.
func TestJS_ProtoPollution_FreshDest_LodashDefaultsDeep(t *testing.T) {
	code := `
const _ = require('lodash');

function processQuery(req) {
    const query = {};
    _.defaultsDeep(query, req.body);
    return query;
}
`
	flows := Analyze(code, "/app/routes/lodash.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow with fresh local `{}` dest")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// _.merge(fresh, src) — Outline / Ghost shape.
func TestJS_ProtoPollution_FreshDest_LodashMerge(t *testing.T) {
	code := `
const _ = require('lodash');

function maskAndForward(req) {
    const fresh = Object.create(null);
    _.merge(fresh, req.body);
    return fresh;
}
`
	flows := Analyze(code, "/app/routes/merge.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow with Object.create(null) fresh dest")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// array.reduce((acc, val) => Object.assign(acc, ...), {}) — accumulator
// is inferred fresh from the initial value `{}`.
func TestJS_ProtoPollution_FreshDest_ReduceAccumulator(t *testing.T) {
	code := `
function combine(items, req) {
    const extra = req.body;
    return items.reduce((acc, v) => Object.assign(acc, extra, v), {});
}
`
	flows := Analyze(code, "/app/routes/reduce.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("did not expect proto-pollution flow for reduce accumulator inferred from `{}` initial")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// _.set(obj, path, value) with a fresh local — STILL flagged because
// path-traversing sinks remain vulnerable on fresh objects (CVE-2020-8203).
func TestJS_ProtoPollution_FreshDest_SetStillFlagged(t *testing.T) {
	code := `
const _ = require('lodash');

app.post('/path-set', (req, res) => {
    const obj = {};
    const path = req.body.path;
    _.set(obj, path, 'value');
    res.json(obj);
});
`
	flows := Analyze(code, "/app/routes/setfresh.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkPrototype) {
		t.Error("expected proto-pollution flow for _.set on fresh local — path traversal still pollutes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
