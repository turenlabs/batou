package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// java.time temporal parsing sanitizers — each parser throws on invalid input
// and returns a strongly-typed object whose toString() is bounded ISO-8601
// format (digits, dashes, colons, T, Z, +) with no characters dangerous to
// SQL, shell, log, file path, HTML, or redirect contexts.

func TestKotlin_Time_Safe_LocalDateParse_SQL(t *testing.T) {
	// Note: avoid `Query(` substring (e.g. executeQuery) — tsflow's
	// isWebHandlerFunc treats it as a web-handler annotation and auto-taints
	// all parameters. executeUpdate is still a SnkSQLQuery sink and avoids
	// the substring trigger.
	code := `
import java.sql.DriverManager
import java.time.LocalDate

fun handler() {
    val userInput = readLine()
    val date = LocalDate.parse(userInput)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE events SET status = 'seen' WHERE day = '" + date + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when LocalDate.parse() restricts input to ISO-8601 (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_LocalDateTimeParse_Log(t *testing.T) {
	code := `
import org.slf4j.LoggerFactory
import java.time.LocalDateTime

fun handler() {
    val logger = LoggerFactory.getLogger("app")
    val userInput = readLine()
    val ts = LocalDateTime.parse(userInput)
    logger.info("event at {}", ts)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when LocalDateTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_InstantParse_Command(t *testing.T) {
	code := `
import java.time.Instant

fun handler() {
    val userInput = readLine()
    val moment = Instant.parse(userInput)
    Runtime.getRuntime().exec("logger event=" + moment.toString())
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence command flow when Instant.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_LocalTimeParse_SQL(t *testing.T) {
	code := `
import java.sql.DriverManager
import java.time.LocalTime

fun handler() {
    val userInput = readLine()
    val t = LocalTime.parse(userInput)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE events SET seen = 1 WHERE hour = '" + t + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when LocalTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_ZonedDateTimeParse_SQL(t *testing.T) {
	code := `
import java.sql.DriverManager
import java.time.ZonedDateTime

fun handler() {
    val userInput = readLine()
    val zdt = ZonedDateTime.parse(userInput)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE events SET seen = 1 WHERE created = '" + zdt + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when ZonedDateTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_OffsetDateTimeParse_Log(t *testing.T) {
	code := `
import org.slf4j.LoggerFactory
import java.time.OffsetDateTime

fun handler() {
    val logger = LoggerFactory.getLogger("app")
    val userInput = readLine()
    val odt = OffsetDateTime.parse(userInput)
    logger.info("event at {}", odt)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when OffsetDateTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_DurationParse_Log(t *testing.T) {
	code := `
import org.slf4j.LoggerFactory
import java.time.Duration

fun handler() {
    val logger = LoggerFactory.getLogger("app")
    val userInput = readLine()
    val d = Duration.parse(userInput)
    logger.info("timeout {}", d)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when Duration.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestKotlin_Time_Safe_PeriodParse_SQL(t *testing.T) {
	code := `
import java.sql.DriverManager
import java.time.Period

fun handler() {
    val userInput = readLine()
    val p = Period.parse(userInput)
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE plans SET seen = 1 WHERE term = '" + p + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when Period.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

// Positive control — without the parse() sanitizer, the same readLine -> SQL
// flow should be detected. Confirms the negative tests above are testing the
// sanitizer effect, not just absent source/sink coverage.
func TestKotlin_Time_Unsafe_NoParse_SQL(t *testing.T) {
	code := `
import java.sql.DriverManager

fun handler() {
    val userInput = readLine()
    val conn = DriverManager.getConnection("jdbc:h2:mem:")
    val stmt = conn.createStatement()
    stmt.executeUpdate("UPDATE events SET seen = 1 WHERE day = '" + userInput + "'")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for readLine -> string concat -> executeQuery() (positive control)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
