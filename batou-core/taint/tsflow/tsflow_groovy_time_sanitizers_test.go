package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// java.time temporal parsing sanitizers — each parser throws on invalid input
// and returns a strongly-typed object whose toString() is bounded ISO-8601
// format (digits, dashes, colons, T, Z, +) with no characters dangerous to
// SQL, shell, log, file path, HTML, or redirect contexts.
//
// Test style mirrors tsflow_groovy_camel_test.go: receiver-named "sql" hits
// the groovy.sql.Sql sinks via the matcher's last-part equality, "logger"
// matches the LoggerFactory/Logger ObjectTypes via prefix-abbreviation, and
// Runtime.getRuntime().exec() is the canonical command sink.

func TestGroovy_Time_Safe_LocalDateParse_SQL(t *testing.T) {
	code := `
import java.time.LocalDate

def handler(userInput) {
    def date = LocalDate.parse(userInput)
    sql.execute("UPDATE events SET status = 'seen' WHERE day = '" + date + "'")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when LocalDate.parse() restricts input to ISO-8601 (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_LocalDateTimeParse_Log(t *testing.T) {
	code := `
import org.slf4j.LoggerFactory
import java.time.LocalDateTime

def handler(userInput) {
    def logger = LoggerFactory.getLogger("app")
    def ts = LocalDateTime.parse(userInput)
    logger.info("event at " + ts)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when LocalDateTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_InstantParse_Command(t *testing.T) {
	code := `
import java.time.Instant

def handler(userInput) {
    def moment = Instant.parse(userInput)
    Runtime.getRuntime().exec("logger event=" + moment.toString())
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence command flow when Instant.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_LocalTimeParse_SQL(t *testing.T) {
	code := `
import java.time.LocalTime

def handler(userInput) {
    def localTime = LocalTime.parse(userInput)
    sql.execute("UPDATE events SET seen = 1 WHERE hour = '" + localTime + "'")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when LocalTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_ZonedDateTimeParse_SQL(t *testing.T) {
	code := `
import java.time.ZonedDateTime

def handler(userInput) {
    def zdt = ZonedDateTime.parse(userInput)
    sql.execute("UPDATE events SET seen = 1 WHERE created = '" + zdt + "'")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when ZonedDateTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_OffsetDateTimeParse_Log(t *testing.T) {
	code := `
import org.slf4j.LoggerFactory
import java.time.OffsetDateTime

def handler(userInput) {
    def logger = LoggerFactory.getLogger("app")
    def odt = OffsetDateTime.parse(userInput)
    logger.info("event at " + odt)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when OffsetDateTime.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_DurationParse_Log(t *testing.T) {
	code := `
import org.slf4j.LoggerFactory
import java.time.Duration

def handler(userInput) {
    def logger = LoggerFactory.getLogger("app")
    def d = Duration.parse(userInput)
    logger.info("timeout " + d)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when Duration.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

func TestGroovy_Time_Safe_PeriodParse_SQL(t *testing.T) {
	code := `
import java.time.Period

def handler(userInput) {
    def p = Period.parse(userInput)
    sql.execute("UPDATE plans SET seen = 1 WHERE term = '" + p + "'")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQL flow when Period.parse() restricts input (conf=%.2f)", f.Confidence)
		}
	}
}

// Positive control — without the parse() sanitizer, the same userInput -> SQL
// flow should be detected. Confirms the negative tests above are testing the
// sanitizer effect, not just absent source/sink coverage.
func TestGroovy_Time_Unsafe_NoParse_SQL(t *testing.T) {
	code := `
def handler(userInput) {
    sql.execute("UPDATE events SET seen = 1 WHERE day = '" + userInput + "'")
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for userInput param -> string concat -> sql.execute() (positive control)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
