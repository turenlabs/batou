package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy open-redirect / dispatch sinks (CWE-601, CWE-22)
//
// These tests cover redirect sinks added in the 2026-04-17 research cycle:
// Spring RedirectView / HttpHeaders.setLocation / ResponseEntity.created,
// JAX-RS Response.seeOther / temporaryRedirect, Grails redirect(uri:) /
// forward(...), and Servlet getRequestDispatcher.
// =========================================================================

func TestGroovy_SpringRedirectView_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def target = params.next
    return new RedirectView(target)
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for params.next -> new RedirectView()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringHttpHeadersSetLocation_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def next = params.next
    def headers = new HttpHeaders()
    headers.setLocation(URI.create(next))
    return headers
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for params.next -> headers.setLocation()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringResponseEntityCreated_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def target = params.newResource
    return ResponseEntity.created(URI.create(target)).build()
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for params.newResource -> ResponseEntity.created()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JaxrsResponseSeeOther_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def next = params.next
    return Response.seeOther(URI.create(next)).build()
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for params.next -> Response.seeOther()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JaxrsResponseTemporaryRedirect_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def next = params.next
    return Response.temporaryRedirect(URI.create(next)).build()
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for params.next -> Response.temporaryRedirect()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GrailsRedirectUri_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def next = params.next
    redirect(uri: next)
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for params.next -> redirect(uri:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_GrailsForward_Tainted(t *testing.T) {
	code := `
def handler(params) {
    def dest = params.target
    forward(action: dest)
}
`
	flows := Analyze(code, "/app/ForwardController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected dispatch-hijack flow for params.target -> forward(action:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ServletGetRequestDispatcher_Tainted(t *testing.T) {
	code := `
def handler(request, response) {
    def page = request.getParameter("page")
    def dispatcher = request.getRequestDispatcher(page)
    dispatcher.forward(request, response)
}
`
	flows := Analyze(code, "/app/DispatchController.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected path-traversal flow for request.getParameter -> getRequestDispatcher()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: static URL literal should not produce a redirect flow even when
// tainted input is present elsewhere.
func TestGroovy_SpringRedirectView_StaticUrl_Safe(t *testing.T) {
	code := `
def handler(params) {
    def logged = params.next
    return new RedirectView("/dashboard")
}
`
	flows := Analyze(code, "/app/RedirectController.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect {
			t.Errorf("unexpected redirect flow for static URL literal: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
