package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy CSV / spreadsheet formula-injection sanitizer tests (CWE-1236).
//
// OpenCSV (com.opencsv.CSVWriter) and Apache Commons CSV
// (org.apache.commons.csv.CSVPrinter) are JVM-wide libraries used identically
// from Groovy and Java. Groovy already had the SnkCSV write sinks
// (groovy.opencsv.csvwriter.writeNext/writeAll, groovy.commonscsv.printRecord)
// but no matching sanitizer, while Java ships java.commons.csv.* in
// java_sanitizers.go. These tests cover the Groovy mirror:
//   groovy.csv.escape_formula_prefix    (tsflow-live, return-value helper)
//   groovy.commons.csv.format_with_quote_all (regex-fallback parity)
//
// The escapeCsvFormula(cell) helper prefixes a leading single quote when a
// cell begins with =, +, -, @ or TAB (the OWASP CSV-injection defense), so
// the returned value is no longer interpreted as a spreadsheet formula.
// =========================================================================

// ---- Baselines: confirm the underlying SnkCSV flow fires unsanitized, so the
// safe tests below cannot pass trivially. ----

func TestGroovy_CSV_Baseline_WriteNext(t *testing.T) {
	code := `
def handler(input) {
    def csvWriter = makeWriter()
    csvWriter.writeNext(["id", input] as String[])
}
`
	flows := Analyze(code, "/app/Export.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV formula-injection flow for parameter -> CSVWriter.writeNext (baseline must fire)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestGroovy_CSV_Baseline_WriteAll(t *testing.T) {
	code := `
def handler(input) {
    def csvWriter = makeWriter()
    csvWriter.writeAll([["id", input]])
}
`
	flows := Analyze(code, "/app/Export.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV formula-injection flow for parameter -> CSVWriter.writeAll (baseline must fire)")
	}
}

func TestGroovy_CSV_Baseline_PrintRecord(t *testing.T) {
	code := `
def handler(input) {
    def csvPrinter = makePrinter()
    csvPrinter.printRecord(input)
}
`
	flows := Analyze(code, "/app/Export.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV formula-injection flow for parameter -> CSVPrinter.printRecord (baseline must fire)")
	}
}

// ---- Sanitized: escapeCsvFormula() return value must neutralize SnkCSV. ----

func TestGroovy_CSV_Safe_EscapeFormula_WriteNext(t *testing.T) {
	code := `
def handler(input) {
    def safe = escapeCsvFormula(input)
    def csvWriter = makeWriter()
    csvWriter.writeNext(["id", safe] as String[])
}
`
	flows := Analyze(code, "/app/Export.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("escapeCsvFormula() should neutralize the CSV formula-injection flow into CSVWriter.writeNext")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestGroovy_CSV_Safe_EscapeFormula_PrintRecord(t *testing.T) {
	code := `
def handler(input) {
    def safe = escapeCsvFormula(input)
    def csvPrinter = makePrinter()
    csvPrinter.printRecord(safe)
}
`
	flows := Analyze(code, "/app/Export.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("escapeCsvFormula() should neutralize the CSV formula-injection flow into CSVPrinter.printRecord")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// ---- Negative control: a non-CSV sanitizer must NOT neutralize SnkCSV.
// Pattern.quote() neutralizes ReDoS/SQL, not CSV-formula injection, so the
// flow must still fire (guards against the sanitizer being applied to the
// wrong category). ----

func TestGroovy_CSV_WrongSanitizer_StillFlows(t *testing.T) {
	code := `
def handler(input) {
    def quoted = java.util.regex.Pattern.quote(input)
    def csvWriter = makeWriter()
    csvWriter.writeNext(["id", quoted] as String[])
}
`
	flows := Analyze(code, "/app/Export.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("Pattern.quote() does not defend CSV-formula injection; the SnkCSV flow must still fire")
	}
}

// ---- Registration check: both new sanitizer IDs are present in the catalog. ----

func TestGroovy_CSV_Sanitizers_Registered(t *testing.T) {
	want := map[string]bool{
		"groovy.csv.escape_formula_prefix":         false,
		"groovy.commons.csv.format_with_quote_all": false,
	}
	for _, s := range taint.SanitizersForLanguage(rules.LangGroovy) {
		if _, ok := want[s.ID]; ok {
			want[s.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected groovy CSV sanitizer %q to be registered", id)
		}
	}
}
