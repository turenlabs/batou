package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- OkHttp response sources ---

func TestKotlin_OkHttp_ResponseString_SQLInjection(t *testing.T) {
	code := `
import okhttp3.OkHttpClient
import okhttp3.Request
import java.sql.DriverManager

fun fetchAndStore() {
    val client = OkHttpClient()
    val request = Request.Builder().url("https://external-api.com/data").build()
    val body = client.newCall(request).execute().body
    val data = body.string()
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + data + "'")
}
`
	flows := Analyze(code, "/app/Api.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from OkHttp response.body?.string() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_OkHttp_ResponseBytes_SQLInjection(t *testing.T) {
	code := `
import okhttp3.OkHttpClient
import okhttp3.Request
import java.sql.DriverManager

fun fetchAndStore() {
    val client = OkHttpClient()
    val request = Request.Builder().url("https://external-api.com/cmd").build()
    val body = client.newCall(request).execute().body
    val data = body.bytes()
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + data + "'")
}
`
	flows := Analyze(code, "/app/Api.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from OkHttp body.bytes() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Ktor client sources ---

func TestKotlin_KtorClient_BodyAsText_XSS(t *testing.T) {
	code := `
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText

suspend fun handler(call: ApplicationCall) {
    val client = HttpClient()
    val response = client.get("https://external.com/content")
    val html = response.bodyAsText()
    call.respondText(html, ContentType.Text.Html)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Ktor client bodyAsText() to respondText()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Fuel HTTP client sources ---

func TestKotlin_Fuel_ResponseString_SQLInjection(t *testing.T) {
	code := `
import com.github.kittinunf.fuel.Fuel
import java.sql.DriverManager

fun fetchData() {
    val (_, _, result) = Fuel.get("https://api.external.com/user").responseString()
    val userData = result.get()
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM orders WHERE user = '" + userData + "'")
}
`
	flows := Analyze(code, "/app/Api.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from Fuel.responseString() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Spring WebClient sources ---

func TestKotlin_SpringWebClient_BodyToMono_CommandInjection(t *testing.T) {
	code := `
import org.springframework.web.reactive.function.client.WebClient

fun fetchAndExec() {
    val spec = WebClient.create().get().uri("https://config-service.internal/cmd").retrieve()
    val command = spec.bodyToMono<String>()
    Runtime.getRuntime().exec(command)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from WebClient bodyToMono() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Spring Data JPA repository sources ---

func TestKotlin_SpringRepository_Find_XSS(t *testing.T) {
	code := `
import org.springframework.data.jpa.repository.JpaRepository

fun handler(call: ApplicationCall, repository: UserRepository) {
    val userId = call.parameters["id"]
    val user = repository.findById(userId)
    call.respondText("<h1>" + user.name + "</h1>", ContentType.Text.Html)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from repository.findById() to respondText()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- JPA query result sources ---

func TestKotlin_JPA_GetResultList_SQLInjection(t *testing.T) {
	code := `
import javax.persistence.EntityManager
import java.sql.DriverManager

fun handler(em: EntityManager) {
    val query = em.createQuery("SELECT u.name FROM User u")
    val name = query.getResultList()
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM audit WHERE user = '" + name + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from getResultList() to executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Firebase Firestore sources ---

func TestKotlin_Firebase_Firestore_ToObject_XSS(t *testing.T) {
	code := `
import com.google.firebase.firestore.DocumentSnapshot

fun handler(call: ApplicationCall, documentSnapshot: DocumentSnapshot) {
    val user = documentSnapshot.toObject<User>()
    call.respondText("<div>" + user.bio + "</div>", ContentType.Text.Html)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow from Firestore toObject() to respondText()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Firebase Realtime Database sources ---

func TestKotlin_Firebase_RTDB_GetValue_CommandInjection(t *testing.T) {
	code := `
import com.google.firebase.database.DataSnapshot

fun onDataChange(dataSnapshot: DataSnapshot) {
    val command = dataSnapshot.getValue<String>()
    Runtime.getRuntime().exec(command)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from DataSnapshot.getValue() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Redis Jedis sources ---

func TestKotlin_Jedis_Get_SQLInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import java.sql.DriverManager

fun handler() {
    val jedis = Jedis("localhost")
    val cachedName = jedis.get("user:name")
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + cachedName + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from jedis.get() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- NIO Files read sources ---

func TestKotlin_NioFiles_ReadAllLines_CommandInjection(t *testing.T) {
	code := `
import java.nio.file.Files
import java.nio.file.Paths

fun processConfig() {
    val lines = Files.readAllLines(Paths.get("/etc/config.txt"))
    val cmd = lines[0]
    Runtime.getRuntime().exec(cmd)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Files.readAllLines() to Runtime.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Kotlin File.readLines source ---

func TestKotlin_FileReadLines_SQLInjection(t *testing.T) {
	code := `
import java.io.File
import java.sql.DriverManager

fun processFile() {
    val lines = File("/data/input.txt").readLines()
    val data = lines[0]
    val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
    val stmt = conn.createStatement()
    stmt.executeQuery("SELECT * FROM users WHERE name = '" + data + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from File.readLines() to stmt.executeQuery()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
