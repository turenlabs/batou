package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- SSRF / URLFetch sanitizer tests ---

func TestKotlin_SSRF_Safe_URIGetScheme(t *testing.T) {
	code := `
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest

fun handler() {
    val userUrl = readLine()
    val uri = URI(userUrl)
    if (uri.getScheme() != "https") {
        throw IllegalArgumentException("Only HTTPS allowed")
    }
    val request = HttpRequest.newBuilder().uri(uri).build()
    HttpClient.newHttpClient().send(request, null)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SSRF flow when URI.getScheme() validates protocol")
		}
	}
}

func TestKotlin_SSRF_Safe_URLGetProtocol(t *testing.T) {
	// getProtocol() sanitizes the derived variable (protocol string).
	// Uses URI (not URL) to avoid URL() constructor being matched as a sink.
	code := `
import java.net.URI

fun handler() {
    val userUrl = readLine()
    val uri = URI(userUrl)
    val protocol = uri.toURL().getProtocol()
    if (protocol != "https") {
        throw IllegalArgumentException("Only HTTPS allowed")
    }
    println(uri)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SSRF flow when URL.getProtocol() validates protocol")
		}
	}
}

func TestKotlin_SSRF_Safe_URIGetAuthority(t *testing.T) {
	code := `
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest

fun handler() {
    val userUrl = readLine()
    val uri = URI(userUrl)
    val authority = uri.getAuthority()
    if (authority != "api.example.com") {
        throw IllegalArgumentException("Invalid host")
    }
    val request = HttpRequest.newBuilder().uri(uri).build()
    HttpClient.newHttpClient().send(request, null)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SSRF flow when URI.getAuthority() validates host")
		}
	}
}

func TestKotlin_SSRF_Safe_GuavaInternetDomainName(t *testing.T) {
	code := `
import com.google.common.net.InternetDomainName
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest

fun handler() {
    val userUrl = readLine()
    val uri = URI(userUrl)
    val domain = InternetDomainName.from(uri.host)
    if (!domain.isUnderPublicSuffix) {
        throw IllegalArgumentException("Invalid domain")
    }
    val request = HttpRequest.newBuilder().uri(uri).build()
    HttpClient.newHttpClient().send(request, null)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SSRF flow when InternetDomainName.from() validates domain")
		}
	}
}

func TestKotlin_SSRF_Safe_SpringUriComponentsBuilder(t *testing.T) {
	// UriComponentsBuilder.fromHttpUrl() sanitizes the constructed URL.
	// The sanitizer must be the outermost call on the assignment RHS.
	code := `
import org.springframework.web.util.UriComponentsBuilder

fun handler() {
    val userPath = readLine()
    val builder = UriComponentsBuilder.fromHttpUrl("https://api.example.com")
    builder.path(userPath)
    val url = builder.build().toUriString()
    println(url)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SSRF flow when UriComponentsBuilder.fromHttpUrl() constrains base URL")
		}
	}
}

func TestKotlin_SSRF_Safe_OWASPEncodeForUri(t *testing.T) {
	code := `
import org.owasp.encoder.Encode
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.URI

fun handler() {
    val userInput = readLine()
    val safeParam = Encode.forUri(userInput)
    val url = "https://api.example.com/search?q=$safeParam"
    val request = HttpRequest.newBuilder().uri(URI(url)).build()
    HttpClient.newHttpClient().send(request, null)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SSRF flow when Encode.forUri() sanitizes input")
		}
	}
}

func TestKotlin_SSRF_Unsafe_DirectFetch(t *testing.T) {
	code := `
import java.net.URL

fun handler() {
    val userUrl = readLine()
    val conn = URL(userUrl).openConnection()
    conn.getInputStream()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for readLine -> URL.openConnection() without validation")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Deserialization sanitizer tests ---

func TestKotlin_Deser_Safe_XStreamAllowTypes(t *testing.T) {
	code := `
import com.thoughtworks.xstream.XStream

fun handler() {
    val userInput = readLine()
    val xstream = XStream()
    xstream.allowTypes(arrayOf(SafeClass::class.java))
    val result = xstream.fromXML(userInput)
    println(result)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.5 {
			t.Error("expected no high-confidence deser flow when XStream.allowTypes() restricts classes")
		}
	}
}

func TestKotlin_Deser_Safe_XStreamSetupDefaultSecurity(t *testing.T) {
	code := `
import com.thoughtworks.xstream.XStream

fun handler() {
    val userInput = readLine()
    val xstream = XStream()
    xstream.setupDefaultSecurity(xstream)
    val result = xstream.fromXML(userInput)
    println(result)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Confidence > 0.5 {
			t.Error("expected no high-confidence deser flow when XStream.setupDefaultSecurity() is configured")
		}
	}
}

// --- SQL Injection sanitizer tests ---

func TestKotlin_SQL_Safe_HibernateSetParameter(t *testing.T) {
	code := `
import javax.persistence.EntityManager

fun handler(em: EntityManager) {
    val userId = readLine()
    val query = em.createQuery("SELECT u FROM User u WHERE u.id = :id")
    query.setParameter("id", userId)
    val result = query.resultList
    println(result)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SQL flow when Query.setParameter() binds values safely")
		}
	}
}

func TestKotlin_SQL_Safe_JooqDSL(t *testing.T) {
	code := `
import org.jooq.impl.DSL
import org.jooq.SQLDialect

fun handler() {
    val userName = readLine()
    val ctx = DSL.using(SQLDialect.POSTGRES)
    val result = DSL.select(DSL.field("name"))
        .from(DSL.table("users"))
        .where(DSL.field("name").eq(userName))
    println(result)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SQL flow when jOOQ DSL.select() builds parameterized query")
		}
	}
}

func TestKotlin_SQL_Safe_JooqParam(t *testing.T) {
	code := `
import org.jooq.impl.DSL

fun handler() {
    val userId = readLine()
    val bound = DSL.param("userId", userId)
    val query = DSL.select().from("users").where(DSL.field("id").eq(bound))
    println(query)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SQL flow when DSL.param() provides parameterized binding")
		}
	}
}

func TestKotlin_SQL_Safe_UUIDFromString(t *testing.T) {
	code := `
import java.util.UUID
import javax.persistence.EntityManager

fun handler(em: EntityManager) {
    val userInput = readLine()
    val safeId = UUID.fromString(userInput)
    val query = em.createQuery("SELECT u FROM User u WHERE u.id = '$safeId'")
    val result = query.resultList
    println(result)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Error("expected no high-confidence SQL flow when UUID.fromString() validates input format")
		}
	}
}

func TestKotlin_SQL_Unsafe_StringConcat(t *testing.T) {
	code := `
import java.sql.Connection

fun handler(conn: Connection) {
    val userId = readLine()
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for readLine -> string concat -> executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
