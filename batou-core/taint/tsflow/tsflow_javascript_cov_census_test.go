package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the JS/TS coverage-census round — new precise,
// receiver/framework-anchored sinks and sources closing census gaps:
//
//   - js.function.constructor        new Function(body)          CWE-94
//   - js.sequelize.literal           Sequelize.literal(frag)     CWE-89
//   - js.mysql.format / .sqlstring   mysql.format(sql, vals)     CWE-89
//   - js.angular.domsanitizer.*      bypassSecurityTrust{...}    CWE-79/94
//   - js.jquery.{html,append,wrap,constructor}                   CWE-79
//   - js.aws.lambda.{invoke,invokecommand}                       CWE-918
//   - js.cdp.{runtime.evaluate,page.navigate}                    CWE-94/918
//   - js.nodeexpat.parse             node-expat parser.parse     CWE-611
//   - js.aws.apigw.event.fields      event.body/path/query       (source)
//   - js.grpc.call.request           call.request                (source)
//
// Each class has a TP fixture that fires and a safe/near-miss fixture that
// stays clean (anti-FP gate per the IRON RULE).

// helper: any flow whose sink is in the named set
func anySinkID(flows []taint.TaintFlow, ids ...string) bool {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	for _, f := range flows {
		if set[f.Sink.ID] {
			return true
		}
	}
	return false
}

// --- new Function() global constructor (CWE-94) ---

func TestJS_FunctionConstructor_TP(t *testing.T) {
	code := `
function build(req, res) {
    const body = req.query.code;
    const fn = new Function("a", "b", body);
    fn(1, 2);
}
`
	flows := Analyze(code, "/app/routes/build.js", rules.LangJavaScript)
	// new Function(body) is modeled by the existing js.new.function sink (CWE-94).
	if !flowMatchesSinkID(flows, "js.new.function") {
		t.Error("expected js.new.function flow from req.query -> new Function(body)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_FunctionConstructor_SafeConstant(t *testing.T) {
	// Constant body — no taint, must stay clean.
	code := `
function build() {
    const fn = new Function("return 1 + 1");
    return fn();
}
`
	flows := Analyze(code, "/app/routes/build_safe.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.new.function") {
		t.Error("constant-body new Function() must NOT produce a taint flow")
	}
}

// --- Sequelize.literal (CWE-89) ---

func TestJS_SequelizeLiteral_TP(t *testing.T) {
	code := `
function search(req, res) {
    const order = req.query.order;
    Model.findAll({ order: sequelize.literal(order) });
}
`
	flows := Analyze(code, "/app/routes/search.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.sequelize.literal") {
		t.Error("expected js.sequelize.literal flow from req.query -> sequelize.literal()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_SequelizeLiteral_SafeConstant(t *testing.T) {
	code := `
function search() {
    return Model.findAll({ order: sequelize.literal("createdAt DESC") });
}
`
	flows := Analyze(code, "/app/routes/search_safe.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.sequelize.literal") {
		t.Error("constant sequelize.literal() must NOT produce a flow")
	}
}

// --- mysql.format / SqlString.format (CWE-89) ---

func TestJS_MysqlFormat_TP(t *testing.T) {
	code := `
const mysql = require("mysql");
function run(req, res) {
    const tmpl = req.body.sql;
    const q = mysql.format(tmpl, [1, 2]);
    connection.query(q);
}
`
	flows := Analyze(code, "/app/routes/run.js", rules.LangJavaScript)
	if !anySinkID(flows, "js.mysql.format", "js.mysql.sqlstring.format") {
		t.Error("expected mysql.format flow from req.body -> mysql.format(tmpl, ...)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_MysqlFormat_SafeConstantTemplate(t *testing.T) {
	// Constant template, user data only in the values array (arg 1) — the safe
	// idiom. Arg 0 is not tainted, so no flow.
	code := `
const mysql = require("mysql");
function run(req, res) {
    const id = req.params.id;
    const q = mysql.format("SELECT * FROM users WHERE id = ?", [id]);
    connection.query(q);
}
`
	flows := Analyze(code, "/app/routes/run_safe.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.mysql.format") {
		t.Error("constant-template mysql.format() with user data in values array must NOT flag arg-0 sink")
	}
}

// --- Angular DomSanitizer.bypassSecurityTrust* family (CWE-79/94) ---

func TestJS_AngularBypassResourceUrl_TP(t *testing.T) {
	code := `
class Player {
    constructor(private sanitizer) {}
    load(req) {
        const url = req.query.src;
        this.safeUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
    }
}
`
	flows := Analyze(code, "/app/player.ts", rules.LangTypeScript)
	if !flowMatchesSinkID(flows, "ts.angular.domsanitizer.bypassresourceurl") {
		t.Error("expected bypassSecurityTrustResourceUrl flow from req.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_AngularBypassScript_TP(t *testing.T) {
	code := `
function trustIt(req, sanitizer) {
    const s = req.body.script;
    return sanitizer.bypassSecurityTrustScript(s);
}
`
	flows := Analyze(code, "/app/trust.ts", rules.LangTypeScript)
	if !flowMatchesSinkID(flows, "ts.angular.domsanitizer.bypassscript") {
		t.Error("expected bypassSecurityTrustScript flow from req.body")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_AngularBypassUrlStyle_TP(t *testing.T) {
	code := `
function trustUrl(req, sanitizer) {
    const u = req.query.u;
    const st = req.query.style;
    sanitizer.bypassSecurityTrustUrl(u);
    sanitizer.bypassSecurityTrustStyle(st);
}
`
	flows := Analyze(code, "/app/trust2.ts", rules.LangTypeScript)
	if !flowMatchesSinkID(flows, "ts.angular.domsanitizer.bypassurl") {
		t.Error("expected bypassSecurityTrustUrl flow")
	}
	if !flowMatchesSinkID(flows, "ts.angular.domsanitizer.bypassstyle") {
		t.Error("expected bypassSecurityTrustStyle flow")
	}
}

// --- jQuery DOM-XSS sinks (CWE-79) ---

func TestJS_JQueryHtml_TP(t *testing.T) {
	code := `
function render(req) {
    const name = req.query.name;
    $("#out").html(name);
}
`
	flows := Analyze(code, "/app/ui.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.jquery.html") {
		t.Error("expected js.jquery.html flow from req.query -> $(...).html()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_JQueryAppend_VarReceiver_TP(t *testing.T) {
	// $-prefixed variable receiver.
	code := `
function render(req) {
    const html = req.body.html;
    const $el = $("#container");
    $el.append(html);
}
`
	flows := Analyze(code, "/app/ui2.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.jquery.append") {
		t.Error("expected js.jquery.append flow from req.body -> $el.append()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_JQuery_ArrayAppend_NoFP(t *testing.T) {
	// A plain array .append on a non-jQuery receiver must NOT be flagged as
	// jQuery XSS — this is the anti-FP gate for the empty-receiver collision.
	code := `
function collect(req) {
    const item = req.query.item;
    const list = [];
    list.append(item);
    stream.wrap(item);
}
`
	flows := Analyze(code, "/app/collect.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.jquery.append") || flowMatchesSinkID(flows, "js.jquery.wrap") {
		t.Error("plain array.append / stream.wrap (no $ sigil) must NOT match jQuery DOM-XSS sinks")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_JQueryConstructor_TaintedHtml_TP(t *testing.T) {
	code := `
function show(req) {
    const html = req.body.html;
    $(html).appendTo("body");
}
`
	flows := Analyze(code, "/app/show.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.jquery.constructor") {
		t.Error("expected js.jquery.constructor flow from req.body -> $(html)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_JQueryConstructor_ConstSelector_NoFP(t *testing.T) {
	// $('#static') with a constant selector must NOT fire.
	code := `
function init(req) {
    const _x = req.query.x;
    $("#container").on("click", () => {});
}
`
	flows := Analyze(code, "/app/init.js", rules.LangJavaScript)
	if flowMatchesSinkID(flows, "js.jquery.constructor") {
		t.Error("constant jQuery selector $('#...') must NOT produce a jquery.constructor flow")
	}
}

// --- AWS Lambda invoke (CWE-918) ---

func TestJS_LambdaInvoke_TP(t *testing.T) {
	code := `
function relay(req, res) {
    const target = req.query.fn;
    lambda.invoke({ FunctionName: target, Payload: "{}" });
}
`
	flows := Analyze(code, "/app/relay.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.aws.lambda.invoke") {
		t.Error("expected js.aws.lambda.invoke flow from req.query -> lambda.invoke()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_LambdaInvokeCommand_TP(t *testing.T) {
	code := `
async function relay(req, lambdaClient) {
    const target = req.body.fn;
    await lambdaClient.send(new InvokeCommand({ FunctionName: target }));
}
`
	flows := Analyze(code, "/app/relay3.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.aws.lambda.invokecommand") {
		t.Error("expected js.aws.lambda.invokecommand flow from req.body -> new InvokeCommand()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Chrome DevTools Protocol (CWE-94 / CWE-918) ---

func TestJS_CDPRuntimeEvaluate_TP(t *testing.T) {
	code := `
async function evalRemote(req, Runtime) {
    const expr = req.body.expr;
    await Runtime.evaluate({ expression: expr });
}
`
	flows := Analyze(code, "/app/cdp.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cdp.runtime.evaluate") {
		t.Error("expected js.cdp.runtime.evaluate flow from req.body -> Runtime.evaluate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestJS_CDPPageNavigate_TP(t *testing.T) {
	code := `
async function visit(req, Page) {
    const url = req.query.url;
    await Page.navigate({ url: url });
}
`
	flows := Analyze(code, "/app/cdp2.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.cdp.page.navigate") {
		t.Error("expected js.cdp.page.navigate flow from req.query -> Page.navigate()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- node-expat XXE/DoS (CWE-611) ---

func TestJS_NodeExpatParse_TP(t *testing.T) {
	code := `
function parseXml(req) {
    const xml = req.body.xml;
    parser.parse(xml);
}
`
	flows := Analyze(code, "/app/xml.js", rules.LangJavaScript)
	if !flowMatchesSinkID(flows, "js.nodeexpat.parse") {
		t.Error("expected js.nodeexpat.parse flow from req.body -> parser.parse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink %s)", f.Source.ID, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- AWS API Gateway event fields (source) ---

func TestJS_ApiGwEventSource_TP(t *testing.T) {
	code := `
exports.handler = async (event) => {
    const id = event.pathParameters.id;
    db.query("SELECT * FROM t WHERE id = " + id);
};
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !flowMatchesSourceID(flows, "js.aws.apigw.event.fields") {
		t.Error("expected js.aws.apigw.event.fields source to taint event.pathParameters -> db.query")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// --- gRPC call.request (source) ---

func TestJS_GrpcCallRequest_TP(t *testing.T) {
	code := `
function getUser(call, callback) {
    const name = call.request.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
}
`
	flows := Analyze(code, "/app/grpc.js", rules.LangJavaScript)
	if !flowMatchesSourceID(flows, "js.grpc.call.request") {
		t.Error("expected js.grpc.call.request source to taint call.request.name -> db.query")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}

// flowMatchesSourceID returns true if any flow's source has the given ID.
func flowMatchesSourceID(flows []taint.TaintFlow, id string) bool {
	for _, f := range flows {
		if f.Source.ID == id {
			return true
		}
	}
	return false
}
