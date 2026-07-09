package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- GraphQL DataFetchingEnvironment sources ---

func TestKotlin_GraphQL_GetArgument_SQLInjection(t *testing.T) {
	code := `
import graphql.schema.DataFetcher
import java.sql.DriverManager

class UserResolver {
    fun fetchUser(env: graphql.schema.DataFetchingEnvironment): String {
        val name: String = env.getArgument("name")
        val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")
        return name
    }
}
`
	flows := Analyze(code, "/app/UserResolver.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getArgument to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_GraphQL_GetArguments_Command(t *testing.T) {
	code := `
class CommandResolver {
    fun runCommand(env: graphql.schema.DataFetchingEnvironment): String {
        val args = env.getArguments()
        Runtime.getRuntime().exec(args)
        return "ok"
    }
}
`
	flows := Analyze(code, "/app/CommandResolver.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from env.getArguments to Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_GraphQL_GetVariables_SQLInjection(t *testing.T) {
	code := `
import java.sql.DriverManager

class VarResolver {
    fun lookup(env: graphql.schema.DataFetchingEnvironment): String {
        val vars = env.getVariables()
        val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM t WHERE v = '" + vars + "'")
        return "ok"
    }
}
`
	flows := Analyze(code, "/app/VarResolver.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getVariables() to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (conf: %.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_GraphQL_GetSource_SQLInjection(t *testing.T) {
	code := `
import java.sql.DriverManager

class PostResolver {
    fun title(env: graphql.schema.DataFetchingEnvironment): String {
        val parent = env.getSource()
        val conn = DriverManager.getConnection("jdbc:sqlite:app.db")
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT title FROM posts WHERE id = '" + parent + "'")
        return "ok"
    }
}
`
	flows := Analyze(code, "/app/PostResolver.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from env.getSource() to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: src=%s sink=%s (conf: %.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

// --- WebSocket sources ---

func TestKotlin_KtorWS_IncomingReceive_Command(t *testing.T) {
	code := `
import io.ktor.server.websocket.*
import io.ktor.websocket.*

fun chatHandler() {
    suspend fun handle() {
        val frame = incoming.receive()
        val text = frame.toString()
        Runtime.getRuntime().exec(text)
    }
}
`
	flows := Analyze(code, "/app/Chat.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from incoming.receive() to Runtime.exec")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> snk=%s (conf: %.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Spring_Message_GetPayload_SQLInjection(t *testing.T) {
	code := `
import org.springframework.messaging.Message
import java.sql.DriverManager

class OrderHandler {
    fun handle(message: Message<String>) {
        val payload = message.getPayload()
        val conn = DriverManager.getConnection("jdbc:sqlite:orders.db")
        val stmt = conn.createStatement()
        stmt.executeQuery("SELECT * FROM orders WHERE ref = '" + payload + "'")
    }
}
`
	flows := Analyze(code, "/app/OrderHandler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from message.getPayload() to executeQuery")
		for _, f := range flows {
			t.Logf("  flow: src=%s -> snk=%s (conf: %.2f)", f.Source.ID, f.Sink.Category, f.Confidence)
		}
	}
}
