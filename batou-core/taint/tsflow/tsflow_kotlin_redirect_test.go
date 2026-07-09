package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------- Spring HttpHeaders.setLocation (CWE-601) ----------

func TestKotlin_SpringHttpHeadersSetLocation(t *testing.T) {
	code := `
import org.springframework.http.HttpHeaders
import java.net.URI

fun redirectHeader() {
    val target = readLine()
    val headers = HttpHeaders()
    headers.setLocation(URI.create(target))
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.spring.httpheaders.setlocation" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for Spring HttpHeaders.setLocation()")
	}
}

// ---------- Spring ResponseEntity.created (CWE-601) ----------

func TestKotlin_SpringResponseEntityCreated(t *testing.T) {
	code := `
import org.springframework.http.ResponseEntity
import java.net.URI

fun created() {
    val target = readLine()
    ResponseEntity.created(URI.create(target)).build()
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.spring.responseentity.created" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for Spring ResponseEntity.created()")
	}
}

// ---------- JAX-RS Response.seeOther (CWE-601) ----------

func TestKotlin_JaxRsResponseSeeOther(t *testing.T) {
	code := `
import javax.ws.rs.core.Response
import java.net.URI

fun seeOther() {
    val target = readLine()
    Response.seeOther(URI.create(target)).build()
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.jaxrs.response.seeother" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for JAX-RS Response.seeOther()")
	}
}

// ---------- JAX-RS Response.temporaryRedirect (CWE-601) ----------

func TestKotlin_JaxRsResponseTemporaryRedirect(t *testing.T) {
	code := `
import javax.ws.rs.core.Response
import java.net.URI

fun tempRedirect() {
    val target = readLine()
    Response.temporaryRedirect(URI.create(target)).build()
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.jaxrs.response.temporaryredirect" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for JAX-RS Response.temporaryRedirect()")
	}
}

// ---------- Servlet getRequestDispatcher (CWE-22 / CWE-601) ----------

func TestKotlin_ServletGetRequestDispatcher(t *testing.T) {
	code := `
fun handler() {
    val target = readLine()
    request.getRequestDispatcher(target)
}
`
	flows := Analyze(code, "/app/ForwardController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.servlet.getrequestdispatcher" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect/traversal finding for servlet getRequestDispatcher()")
	}
}

// ---------- Micronaut HttpResponse.redirect (CWE-601) ----------

func TestKotlin_MicronautHttpResponseRedirect(t *testing.T) {
	code := `
import io.micronaut.http.HttpResponse
import java.net.URI

fun redirect() {
    val target = readLine()
    HttpResponse.redirect<Any>(URI.create(target))
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.micronaut.httpresponse.redirect" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for Micronaut HttpResponse.redirect()")
	}
}

// ---------- Micronaut HttpResponse.seeOther (slash-OR method name) ----------

func TestKotlin_MicronautHttpResponseSeeOther(t *testing.T) {
	code := `
import io.micronaut.http.HttpResponse
import java.net.URI

fun see() {
    val target = readLine()
    HttpResponse.seeOther<Any>(URI.create(target))
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.micronaut.httpresponse.redirect" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for Micronaut HttpResponse.seeOther()")
	}
}
