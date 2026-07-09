package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// CSV / spreadsheet formula injection (CWE-1236) — encoding/csv WriteAll
//
// (*csv.Writer).WriteAll([][]string) writes a batch of records. When the
// records hold user-controlled cell values, strings beginning with =, +,
// -, @, tab or CR are interpreted as formulas by Excel / LibreOffice /
// Google Sheets when the exported file is opened (DDE / command execution
// on the viewer's machine). The sink is receiver-bound to *csv.Writer; the
// dangerous arg is the [][]string records slice.
//
// astflow needs the receiver's type to be known (function parameter or
// package-level var declaration) — it does not infer the type of a
// `cw := csv.NewWriter(...)` short-var assignment. The test below uses the
// parameter form, which is the realistic shape for a CSV-export helper.
// =========================================================================

func TestAnalyzeGo_CSVInjection_WriteAll(t *testing.T) {
	code := `package main

import (
	"encoding/csv"
	"net/http"
)

func writeRows(cw *csv.Writer, r *http.Request) {
	name := r.FormValue("name")
	rows := [][]string{{"id", name}}
	cw.WriteAll(rows)
}
`
	flows := AnalyzeGo(code, "/app/export.go")
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for r.FormValue -> [][]string -> (*csv.Writer).WriteAll")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestAnalyzeGo_CSVInjection_WriteAll_HardcodedSafe(t *testing.T) {
	code := `package main

import (
	"encoding/csv"
	"os"
)

func writeStatic() {
	cw := csv.NewWriter(os.Stdout)
	rows := [][]string{{"id", "name", "static"}}
	cw.WriteAll(rows)
}
`
	flows := AnalyzeGo(code, "/app/export.go")
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected NO CSV/formula injection flow when only hardcoded records are written")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
