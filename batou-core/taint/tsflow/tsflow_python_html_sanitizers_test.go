package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Tests for two genuinely-missing Python HTML/XSS output sanitizers:
//
//   - py.lxml.clean_html : lxml.html.clean Cleaner.clean_html() and the
//     module-level clean_html() strip dangerous markup, neutralizing
//     SnkHTMLOutput. lxml is one of the most widely used Python libraries and
//     its HTML cleaner is the documented XSS-prevention path for lxml users.
//   - py.nh3.clean_text  : nh3.clean_text() HTML-escapes a plain string for
//     safe text embedding (companion to the already-modeled nh3.clean).
//
// Each sanitized test pairs a tainted Flask request param flowing into a
// make_response() HTML sink and asserts SnkHTMLOutput is cleared. The
// Unsanitized baseline confirms the raw source -> sink path IS detected
// without the sanitizer so the sanitized tests aren't passing vacuously.
//
// All call sites are wrapped in `def handler()` because the Python tsflow
// walker only descends into function_definition bodies.
// =========================================================================

func TestPython_HTMLSanitizer_Unsanitized_Baseline(t *testing.T) {
	code := `
from flask import request, make_response

def handler():
    name = request.args.get("name")
    return make_response("<p>" + name + "</p>")
`
	flows := Analyze(code, "/app/view.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Fatal("expected SnkHTMLOutput flow when raw request param reaches make_response")
	}
}

func TestPython_LxmlCleanHtml_Module_Sanitized(t *testing.T) {
	code := `
from lxml.html.clean import clean_html
from flask import request, make_response

def handler():
    name = request.args.get("name")
    safe = clean_html(name)
    return make_response("<p>" + safe + "</p>")
`
	flows := Analyze(code, "/app/view.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("clean_html() should neutralize SnkHTMLOutput taint")
		}
	}
}

func TestPython_LxmlCleanHtml_Method_Sanitized(t *testing.T) {
	code := `
from lxml.html.clean import Cleaner
from flask import request, make_response

def handler():
    name = request.args.get("name")
    cleaner = Cleaner()
    safe = cleaner.clean_html(name)
    return make_response("<p>" + safe + "</p>")
`
	flows := Analyze(code, "/app/view.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("Cleaner().clean_html() should neutralize SnkHTMLOutput taint")
		}
	}
}

func TestPython_Nh3CleanText_Sanitized(t *testing.T) {
	code := `
import nh3
from flask import request, make_response

def handler():
    name = request.args.get("name")
    safe = nh3.clean_text(name)
    return make_response("<p>" + safe + "</p>")
`
	flows := Analyze(code, "/app/view.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("nh3.clean_text() should neutralize SnkHTMLOutput taint")
		}
	}
}

// Guards the ObjectType:"nh3" scoping on py.nh3.clean_text: a clean_text()
// method on some unrelated receiver must NOT be treated as the nh3 sanitizer,
// otherwise any object's clean_text() would silently mask real XSS.
func TestPython_Nh3CleanText_OtherReceiver_NotSanitizer(t *testing.T) {
	code := `
from flask import request, make_response

def handler():
    name = request.args.get("name")
    safe = formatter.clean_text(name)
    return make_response("<p>" + safe + "</p>")
`
	flows := Analyze(code, "/app/view.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("formatter.clean_text() must not be mistaken for nh3.clean_text — SnkHTMLOutput flow should still fire")
	}
}
