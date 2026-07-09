package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — Foundation temporal-parse sanitizer tests
// (DateFormatter / ISO8601DateFormatter / NumberFormatter)
//
// All three return-value sanitizers fit the cycle #757 sanitizer model:
// `let typed = recv.<method>(from: tainted)` — the LHS is treated as
// untainted for the Neutralizes set. Direct interpolation `\(typed)` of the
// resulting Date / NSNumber yields a controlled string with none of the
// original bytes preserved.
//
// The matcher's prefix-abbreviation path is the load-bearing piece:
//
//   - receiver "dateFormatter"   → "DateFormatter"          (direct equality)
//   - receiver "iso"             → "ISO8601DateFormatter"   (HasPrefix)
//   - receiver "numberFormatter" → "NumberFormatter"        (direct equality)
//
// These idiomatic Swift names are the canonical Foundation pattern.
// =========================================================================

// -------------------------------------------------------------------------
// Registration check — all three new sanitizer IDs are present
// -------------------------------------------------------------------------

func TestSwift_TemporalSanitizers_Registered(t *testing.T) {
	want := []string{
		"swift.dateformatter.datefromstring",
		"swift.iso8601dateformatter.datefromstring",
		"swift.numberformatter.numberfromstring",
	}
	got := map[string]bool{}
	for _, s := range taint.SanitizersForLanguage(rules.LangSwift) {
		got[s.ID] = true
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("sanitizer %q not registered for Swift", id)
		}
	}
}

// -------------------------------------------------------------------------
// Vulnerable controls — baseline must produce the flow, otherwise the
// "safe" tests are not actually exercising the sanitizer.
// -------------------------------------------------------------------------

// Baseline: raw `req.query["..."]` interpolated into `db.execute(...)` must
// produce a SnkSQLQuery flow. If this fails, the SQL sink (Connection.execute)
// or the source extractor is broken and the safe tests below are meaningless.
func TestSwift_Temporal_SQLBaseline_Unsanitized(t *testing.T) {
	code := `
import Vapor
import SQLite

func handler(req: Request) throws {
    let userInput = req.query["d"]
    let db = try Connection("file.sqlite")
    try db.execute("UPDATE events SET created = '\(userInput)' WHERE id = 1")
}
`
	flows := Analyze(code, "/app/Baseline.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for req.query -> db.execute baseline")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f, id: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Safe: DateFormatter.date(from: tainted) neutralizes SnkSQLQuery
// -------------------------------------------------------------------------

func TestSwift_DateFormatter_DateFrom_Sanitized(t *testing.T) {
	code := `
import Vapor
import SQLite

func handler(req: Request) throws {
    let userInput = req.query["d"]
    let dateFormatter = DateFormatter()
    dateFormatter.dateFormat = "yyyy-MM-dd"
    let parsed = dateFormatter.date(from: userInput)
    let db = try Connection("file.sqlite")
    try db.execute("UPDATE events SET created = '\(parsed)' WHERE id = 1")
}
`
	flows := Analyze(code, "/app/SafeDF.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SnkSQLQuery flow when DateFormatter.date(from:) is in the path: %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Safe: ISO8601DateFormatter.date(from: tainted) neutralizes SnkSQLQuery
// -------------------------------------------------------------------------

func TestSwift_ISO8601DateFormatter_DateFrom_Sanitized(t *testing.T) {
	code := `
import Vapor
import SQLite

func handler(req: Request) throws {
    let userInput = req.query["d"]
    let iso = ISO8601DateFormatter()
    let parsed = iso.date(from: userInput)
    let db = try Connection("file.sqlite")
    try db.execute("UPDATE events SET created = '\(parsed)' WHERE id = 1")
}
`
	flows := Analyze(code, "/app/SafeISO.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SnkSQLQuery flow when ISO8601DateFormatter.date(from:) is in the path: %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Safe: NumberFormatter.number(from: tainted) neutralizes SnkSQLQuery
// -------------------------------------------------------------------------

func TestSwift_NumberFormatter_NumberFrom_Sanitized(t *testing.T) {
	code := `
import Vapor
import SQLite

func handler(req: Request) throws {
    let userInput = req.query["amount"]
    let numberFormatter = NumberFormatter()
    numberFormatter.numberStyle = .decimal
    let n = numberFormatter.number(from: userInput)
    let db = try Connection("file.sqlite")
    try db.execute("UPDATE accounts SET balance = \(n) WHERE id = 1")
}
`
	flows := Analyze(code, "/app/SafeNF.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("expected NO SnkSQLQuery flow when NumberFormatter.number(from:) is in the path: %s -> %s (id: %s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// -------------------------------------------------------------------------
// Negative regressions
// -------------------------------------------------------------------------

// Constant string: a fully-literal DateFormatter.date(from:) call with no
// tainted input must produce zero flows — guards against the sanitizer
// pattern accidentally being treated as a source.
func TestSwift_DateFormatter_ConstantString_NoFlow(t *testing.T) {
	code := `
import Vapor
import SQLite

func handler() throws {
    let dateFormatter = DateFormatter()
    let parsed = dateFormatter.date(from: "2026-01-01")
    let db = try Connection("file.sqlite")
    try db.execute("UPDATE events SET created = '\(parsed)' WHERE id = 1")
}
`
	flows := Analyze(code, "/app/ConstDF.swift", rules.LangSwift)
	if len(flows) != 0 {
		t.Errorf("expected zero flows for constant-string DateFormatter.date(from:), got %d", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f, id: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}

// Negative control: a fake `noopFormatter.date(from: tainted)` whose receiver
// name doesn't match the DateFormatter heuristic must NOT suppress the SQLi
// flow. Confirms that the sanitizer's ObjectType constraint is real, not a
// blanket pass on any `.date(from:)` call.
func TestSwift_FakeFormatter_NoSpuriousSanitization(t *testing.T) {
	code := `
import Vapor
import SQLite

func handler(req: Request) throws {
    let userInput = req.query["d"]
    let unrelated = SomeOtherThing()
    let parsed = unrelated.date(from: userInput)
    let db = try Connection("file.sqlite")
    try db.execute("UPDATE events SET created = '\(parsed)' WHERE id = 1")
}
`
	flows := Analyze(code, "/app/FakeDF.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow even when an unrelated `.date(from:)` call is in the path — sanitizer must require DateFormatter-family receiver")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f, id: %s)", f.Source.Category, f.Sink.Category, f.Confidence, f.Sink.ID)
		}
	}
}
