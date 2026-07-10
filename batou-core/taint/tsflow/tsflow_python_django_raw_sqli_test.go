package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Django ORM raw() SQL injection (CWE-89) — regression coverage for the
// dead-ObjectType fix.
//
// The `py.django.orm.raw` sink previously carried
// ObjectType:"django.db.models.Manager" — a framework type name that no real
// receiver expression ever carries. Django raw() is always invoked as
// `<Model>.objects.raw(...)`, so the receiver of the `.raw(` call is
// `<Model>.objects` and the structural matcher could never bridge it to the
// "Manager" type, leaving the sink permanently dead (the pygoat
// `login.objects.raw(sql_query)` SQLi was 0 dataflow findings). The fix flips
// the ObjectType to wildcard ("") and anchors the Pattern on `.objects.raw(`.
// =========================================================================

// LOAD-BEARING: this is exactly the pygoat shape — request source concatenated
// into a SQL string passed to <Model>.objects.raw(...). It MUST fire CWE-89.
// Reverting the catalog entry (ObjectType back to the framework type name)
// makes this test fail.
func TestPython_DjangoObjectsRaw_SQLi(t *testing.T) {
	code := `
def lab(request):
    name = request.POST.get('name')
    sql_query = "SELECT * FROM introduction_login WHERE user='" + name + "'"
    val = login.objects.raw(sql_query)
    return val
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-89") {
		t.Error("expected CWE-89 SQL injection flow from request.POST -> login.objects.raw()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, conf=%.2f)",
				f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.Confidence)
		}
	}
}

// Direct inline source in the raw() argument (no intermediate variable).
func TestPython_DjangoObjectsRaw_SQLi_Inline(t *testing.T) {
	code := `
def lab(request):
    val = MyModel.objects.raw("SELECT * FROM t WHERE id = " + request.GET.get('id'))
    return val
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlowCWE(flows, "CWE-89") {
		t.Error("expected CWE-89 SQL injection flow from inline request source -> objects.raw()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, conf=%.2f)",
				f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.Confidence)
		}
	}
}

// NEGATIVE: parameterized raw() (placeholder + params list) is the SAFE Django
// idiom and must NOT produce a SQL-injection flow — the tainted value is bound,
// not concatenated into the query string.
func TestPython_DjangoObjectsRaw_Parameterized_Safe(t *testing.T) {
	code := `
def lab(request):
    name = request.POST.get('name')
    val = login.objects.raw("SELECT * FROM t WHERE user = %s", [name])
    return val
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Sink.ID == "py.django.orm.raw" {
			t.Errorf("parameterized objects.raw() must not flag SQLi (id=%s, cwe=%s)",
				f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// NEGATIVE: a non-Django `.raw(` call (e.g. requests' streaming `response.raw`
// is an attribute, but even an unrelated `.raw(` method on a different object
// without the `.objects.` chain) must NOT match this sink — the anchored
// Pattern requires `.objects.raw(`.
func TestPython_NonDjangoRaw_NotSQLi(t *testing.T) {
	code := `
def handler(request):
    payload = request.GET.get('q')
    resp = some_client.raw(payload)
    return resp
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.ID == "py.django.orm.raw" {
			t.Errorf("non-Django .raw() must not match py.django.orm.raw (cwe=%s)", f.Sink.CWEID)
		}
	}
}
