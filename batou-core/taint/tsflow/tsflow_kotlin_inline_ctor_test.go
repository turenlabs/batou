package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Kotlin inline-constructor-receiver dead-keying (CWE-502 deser / CWE-918 SSRF).
// A sink whose idiomatic call is `Type().method(tainted)` (snakeyaml Yaml().load,
// OkHttp Request.Builder().url, Gson().fromJson) was dead-keyed: the matcher
// derives the receiver as `Yaml()` / `Request.Builder()` (trailing parens), which
// never equals the catalog's framework-FQN ObjectType last component, so the sink
// never matched. Re-keyed to wildcard ObjectType + bare MethodName with the tight
// call-anchored Pattern as the anchor. The var-form (`yaml.load(x)`) was already
// live and must stay live; the const form must stay clean.

func TestKotlin_InlineCtor_SnakeYaml_Load_Deser(t *testing.T) {
	code := `
fun handler() {
    val d = readLine()
    val obj = Yaml().load(d)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected CWE-502 deserialize flow for readLine -> Yaml().load() (inline-ctor)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_InlineCtor_OkHttp_Url_SSRF(t *testing.T) {
	code := `
fun handler() {
    val u = readLine()
    val req = Request.Builder().url(u).build()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected CWE-918 SSRF flow for readLine -> Request.Builder().url() (inline-ctor)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_InlineCtor_Gson_FromJson_Deser(t *testing.T) {
	code := `
fun handler() {
    val d = readLine()
    val obj = Gson().fromJson(d)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected CWE-502 deserialize flow for readLine -> Gson().fromJson() (inline-ctor)")
	}
}

// Var-form must STAY live (the already-working path the Pattern alt preserves).
func TestKotlin_VarForm_SnakeYaml_Load_StillFires(t *testing.T) {
	code := `
fun handler() {
    val d = readLine()
    val obj = yaml.load(d)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("var-form yaml.load(tainted) must STILL fire CWE-502 (regression)")
	}
}

// Negative: a constant argument must NOT produce a deserialize flow.
func TestKotlin_InlineCtor_SnakeYaml_Const_NoFlow(t *testing.T) {
	code := `
fun handler() {
    val obj = Yaml().load("a: 1")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("constant Yaml().load(literal) must NOT fire CWE-502 (false positive)")
	}
}
