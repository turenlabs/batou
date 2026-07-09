package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// CSV / spreadsheet formula injection (CWE-1236) — SnkCSV
//
// Untrusted data written into a CSV/spreadsheet cell where a value beginning
// with =, +, -, @, tab or CR is interpreted as a formula by Excel /
// LibreOffice / Google Sheets when the exported file is opened, enabling
// DDE / command execution on the viewer's machine. The sink is the CSV
// row/field write call; the dangerous arg is the row/data being written.
// =========================================================================

// --- Python: csv.writer().writerow / writerows ---

func TestPython_CSV_Writer_Writerow(t *testing.T) {
	code := `
import csv
from flask import request

def export():
    name = request.args.get("name")
    with open("out.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", name])
`
	flows := Analyze(code, "/app/export.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for request.args.get -> csv.writer().writerow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

func TestPython_CSV_Writer_Writerows(t *testing.T) {
	code := `
import csv
from flask import request

def export():
    rows = request.get_json()
    with open("out.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerows(rows)
`
	flows := Analyze(code, "/app/export.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for request.get_json -> csv.writer().writerows")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Python: hardcoded literal must NOT flag ---

func TestPython_CSV_Writer_HardcodedSafe(t *testing.T) {
	code := `
import csv

def export():
    with open("out.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "name", "static"])
`
	flows := Analyze(code, "/app/export.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected NO CSV/formula injection flow when only hardcoded literals are written")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- JavaScript: papaparse Papa.unparse ---

func TestJS_CSV_Papa_Unparse(t *testing.T) {
	code := `
const Papa = require("papaparse");

app.get("/export", (req, res) => {
    const term = req.query.q;
    const rows = [{ id: 1, name: term }];
    const csv = Papa.unparse(rows);
    res.send(csv);
});
`
	flows := Analyze(code, "/app/routes/export.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for req.query -> Papa.unparse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- JavaScript: hardcoded literal must NOT flag ---

func TestJS_CSV_Papa_Unparse_HardcodedSafe(t *testing.T) {
	code := `
const Papa = require("papaparse");

function exportStatic() {
    const rows = [{ id: 1, name: "static" }];
    return Papa.unparse(rows);
}
`
	flows := Analyze(code, "/app/export.js", rules.LangJavaScript)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected NO CSV/formula injection flow when only hardcoded literals are unparsed")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Java: opencsv CSVWriter.writeNext ---

func TestJava_CSV_OpenCSV_WriteNext(t *testing.T) {
	code := `
import javax.servlet.http.*;
import com.opencsv.CSVWriter;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        CSVWriter writer = new CSVWriter(new java.io.FileWriter("out.csv"));
        String[] row = new String[]{ "id", name };
        writer.writeNext(row);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for getParameter -> CSVWriter.writeNext")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Java: Apache Commons CSV CSVPrinter.printRecord ---

func TestJava_CSV_CommonsCSV_PrintRecord(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVFormat;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        CSVPrinter printer = new CSVPrinter(new java.io.FileWriter("out.csv"), CSVFormat.DEFAULT);
        printer.printRecord("id", name);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for getParameter -> CSVPrinter.printRecord")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- PHP: fputcsv($handle, $fields) ---

func TestPHP_CSV_Fputcsv(t *testing.T) {
	code := `<?php
function export() {
    $name = $_GET["name"];
    $fp = fopen("out.csv", "w");
    $fields = array("id", $name);
    fputcsv($fp, $fields);
}
?>`
	flows := Analyze(code, "/app/export.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for $_GET -> fputcsv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- PHP: hardcoded literal must NOT flag ---

func TestPHP_CSV_Fputcsv_HardcodedSafe(t *testing.T) {
	code := `<?php
function export() {
    $fp = fopen("out.csv", "w");
    $fields = array("id", "name", "static");
    fputcsv($fp, $fields);
}
?>`
	flows := Analyze(code, "/app/export.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected NO CSV/formula injection flow when only hardcoded literals are written")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
