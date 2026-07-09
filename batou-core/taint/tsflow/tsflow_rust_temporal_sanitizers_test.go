package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for Rust temporal parsing sanitizers (chrono / time / humantime).
//
// Same model as the Kotlin time-parse sanitizers (PR #600): once user input
// is parsed into a strongly-typed Date / DateTime / Duration value, its
// Display impl is well-defined (ISO-8601 / RFC formats) and cannot carry
// shell metachars, SQL syntax, path separators, CRLFs, HTML, or
// scheme-injection payloads.
//
// Each sanitizer has a paired "Vulnerable" test (asserting the
// env::var -> sqlx::query flow IS detected without the sanitizer) and a
// "Safe" test (asserting the flow is neutralized when the sanitizer is
// applied inline).
//
// The "Safe" tests inline the sanitizer call directly inside the sink's
// argument list so the walker's containsInlineSanitizer pass picks it up
// without depending on .unwrap() chain handling (the walker's let-RHS
// sanitizer path fires only on the outermost call, which would be
// .unwrap() rather than the parser).

// --- Registration check ---

func TestRust_TemporalSanitizers_Registered(t *testing.T) {
	want := []string{
		"rust.chrono.datetime.parse_from_rfc3339",
		"rust.chrono.datetime.parse_from_rfc2822",
		"rust.chrono.datetime.parse_from_str",
		"rust.chrono.naivedate.parse_from_str",
		"rust.chrono.naivedatetime.parse_from_str",
		"rust.chrono.naivetime.parse_from_str",
		"rust.time.offsetdatetime.parse",
		"rust.time.primitivedatetime.parse",
		"rust.humantime.parse_duration",
		"rust.humantime.parse_rfc3339",
	}

	got := make(map[string]bool)
	for _, s := range taint.SanitizersForLanguage(rules.LangRust) {
		got[s.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected sanitizer %q to be registered for Rust", id)
		}
	}
}

// --- Vulnerable control: source -> sqlx::query without sanitizer ---

func TestRust_TemporalSanitizers_Vulnerable_SqlxQuery(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let input = env::var("CREATED_AT").unwrap();
    let _ = sqlx::query(input).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for env::var -> sqlx::query (control)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.ID, f.Sink.ID, f.Confidence)
		}
	}
}

// --- chrono::DateTime parsers ---

func TestRust_Chrono_DateTime_ParseFromRfc3339_Safe(t *testing.T) {
	code := `
use std::env;
use chrono::DateTime;

async fn handler() {
    let input = env::var("CREATED_AT").unwrap();
    let _ = sqlx::query(chrono::DateTime::parse_from_rfc3339(&input)).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("DateTime::parse_from_rfc3339 should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Chrono_DateTime_ParseFromRfc2822_Safe(t *testing.T) {
	code := `
use std::env;
use chrono::DateTime;

async fn handler() {
    let input = env::var("HEADER_DATE").unwrap();
    let _ = sqlx::query(chrono::DateTime::parse_from_rfc2822(&input)).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("DateTime::parse_from_rfc2822 should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Chrono_DateTime_ParseFromStr_Safe(t *testing.T) {
	code := `
use std::env;
use chrono::DateTime;

async fn handler() {
    let input = env::var("CUSTOM_DATE").unwrap();
    let _ = sqlx::query(chrono::DateTime::parse_from_str(&input, "%Y-%m-%d %H:%M:%S")).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("DateTime::parse_from_str should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Chrono_NaiveDate_ParseFromStr_Safe(t *testing.T) {
	code := `
use std::env;
use chrono::NaiveDate;

async fn handler() {
    let input = env::var("DOB").unwrap();
    let _ = sqlx::query(chrono::NaiveDate::parse_from_str(&input, "%Y-%m-%d")).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("NaiveDate::parse_from_str should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Chrono_NaiveDateTime_ParseFromStr_Safe(t *testing.T) {
	code := `
use std::env;
use chrono::NaiveDateTime;

async fn handler() {
    let input = env::var("EVENT_TIME").unwrap();
    let _ = sqlx::query(chrono::NaiveDateTime::parse_from_str(&input, "%Y-%m-%d %H:%M:%S")).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("NaiveDateTime::parse_from_str should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Chrono_NaiveTime_ParseFromStr_Safe(t *testing.T) {
	code := `
use std::env;
use chrono::NaiveTime;

async fn handler() {
    let input = env::var("CLOCK").unwrap();
    let _ = sqlx::query(chrono::NaiveTime::parse_from_str(&input, "%H:%M:%S")).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("NaiveTime::parse_from_str should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- time crate parsers ---

func TestRust_Time_OffsetDateTime_Parse_Safe(t *testing.T) {
	code := `
use std::env;
use time::OffsetDateTime;

async fn handler() {
    let input = env::var("CREATED_AT").unwrap();
    let _ = sqlx::query(time::OffsetDateTime::parse(&input, &Rfc3339)).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("time::OffsetDateTime::parse should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Time_PrimitiveDateTime_Parse_Safe(t *testing.T) {
	code := `
use std::env;
use time::PrimitiveDateTime;

async fn handler() {
    let input = env::var("EVENT_AT").unwrap();
    let _ = sqlx::query(time::PrimitiveDateTime::parse(&input, &Rfc3339)).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("time::PrimitiveDateTime::parse should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

// --- humantime crate parsers ---

func TestRust_Humantime_ParseDuration_Safe(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let input = env::var("TIMEOUT").unwrap();
    let _ = sqlx::query(humantime::parse_duration(&input)).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("humantime::parse_duration should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}

func TestRust_Humantime_ParseRfc3339_Safe(t *testing.T) {
	code := `
use std::env;

async fn handler() {
    let input = env::var("CREATED_AT").unwrap();
    let _ = sqlx::query(humantime::parse_rfc3339(&input)).fetch_all(&pool).await;
}
`
	flows := Analyze(code, "/app/events.rs", rules.LangRust)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("humantime::parse_rfc3339 should sanitize input before sqlx::query: %s -> %s",
				f.Source.ID, f.Sink.ID)
		}
	}
}
