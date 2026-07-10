package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# CSV / spreadsheet formula injection (CWE-1236) — SnkCSV
//
// Untrusted data written into a CSV/TSV cell where a value beginning with
// =, +, -, @, tab or CR is interpreted as a formula by Excel / LibreOffice /
// Google Sheets when the exported file is opened, enabling DDE / command
// execution on the viewer's machine. CsvHelper (the dominant .NET CSV library)
// ships injection protection only as an opt-in CsvConfiguration setting, so a
// default-configured CsvWriter is vulnerable. ServiceStack.Text's
// CsvSerializer.SerializeToString has the same risk.
// ===========================================================================

// --- CsvHelper: CsvWriter.WriteField(field) — direct string flow ---

func TestCSharp_CSV_CsvHelper_WriteField(t *testing.T) {
	code := `
using System.Globalization;
using CsvHelper;
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller {
    public IActionResult Export() {
        string name = Request.QueryString.Value;
        using var writer = new StreamWriter("out.csv");
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
        csv.WriteField(name);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ExportController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for Request.QueryString -> CsvWriter.WriteField")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s, conf=%.2f)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID, f.Confidence)
		}
	}
}

// --- CsvHelper: CsvWriter.WriteRecord(record) ---

func TestCSharp_CSV_CsvHelper_WriteRecord(t *testing.T) {
	code := `
using System.Globalization;
using CsvHelper;
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller {
    public IActionResult Export() {
        string record = Request.QueryString.Value;
        using var writer = new StreamWriter("out.csv");
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
        csv.WriteRecord(record);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ExportController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for Request.QueryString -> CsvWriter.WriteRecord")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- CsvHelper: CsvWriter.WriteRecords(records) ---

func TestCSharp_CSV_CsvHelper_WriteRecords(t *testing.T) {
	code := `
using System.Globalization;
using CsvHelper;
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller {
    public IActionResult Export() {
        string rows = Request.QueryString.Value;
        using var writer = new StreamWriter("out.csv");
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
        csv.WriteRecords(rows);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ExportController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for Request.QueryString -> CsvWriter.WriteRecords")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- CsvHelper: CsvWriter.WriteRecordsAsync(records) ---

func TestCSharp_CSV_CsvHelper_WriteRecordsAsync(t *testing.T) {
	code := `
using System.Globalization;
using System.Threading.Tasks;
using CsvHelper;
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller {
    public async Task<IActionResult> Export() {
        string rows = Request.QueryString.Value;
        using var writer = new StreamWriter("out.csv");
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
        await csv.WriteRecordsAsync(rows);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ExportController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for Request.QueryString -> CsvWriter.WriteRecordsAsync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- ServiceStack.Text: CsvSerializer.SerializeToString(records) ---

func TestCSharp_CSV_ServiceStack_SerializeToString(t *testing.T) {
	code := `
using ServiceStack.Text;
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller {
    public IActionResult Export() {
        string records = Request.QueryString.Value;
        string csv = CsvSerializer.SerializeToString(records);
        return Content(csv);
    }
}
`
	flows := Analyze(code, "/app/ExportController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected CSV/formula injection flow for Request.QueryString -> CsvSerializer.SerializeToString")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s, cwe=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID, f.Sink.CWEID)
		}
	}
}

// --- Negative: hardcoded literals must NOT flag ---

func TestCSharp_CSV_CsvHelper_HardcodedSafe(t *testing.T) {
	code := `
using System.Globalization;
using CsvHelper;

public class Report {
    public void Export() {
        using var writer = new StreamWriter("out.csv");
        using var csv = new CsvWriter(writer, CultureInfo.InvariantCulture);
        csv.WriteField("id");
        csv.WriteField("name");
        csv.WriteField("static");
    }
}
`
	flows := Analyze(code, "/app/Report.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected NO CSV/formula injection flow when only hardcoded literals are written")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Negative: unrelated object's WriteField must NOT flag ---
// `writer` is a plain object whose name is not a prefix of "csvwriter", so the
// CsvHelper.CsvWriter-scoped sink should not match even though the method name
// happens to be "WriteField".

func TestCSharp_CSV_UnrelatedWriteField_NoFlag(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

public class ExportController : Controller {
    public IActionResult Export() {
        string name = Request.QueryString.Value;
        var protoWriter = new SomeProtoWriter();
        protoWriter.WriteField(name);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ExportController.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkCSV) {
		t.Error("expected NO CSV/formula injection flow for an unrelated object's WriteField (receiver 'protoWriter' is not CsvHelper.CsvWriter)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

// --- Registration check ---

func TestCSharp_CSV_SinkRegistration(t *testing.T) {
	sinks := taint.SinksForLanguage(rules.LangCSharp)
	want := []string{
		"csharp.csvhelper.writefield",
		"csharp.csvhelper.writerecord",
		"csharp.csvhelper.writerecords",
		"csharp.csvhelper.writerecordsasync",
		"csharp.servicestack.csvserializer.serializetostring",
	}
	for _, id := range want {
		found := false
		for _, s := range sinks {
			if s.ID == id {
				found = true
				if s.Category != taint.SnkCSV {
					t.Errorf("sink %s: expected category SnkCSV, got %v", id, s.Category)
				}
				if s.CWEID != "CWE-1236" {
					t.Errorf("sink %s: expected CWE-1236, got %s", id, s.CWEID)
				}
				break
			}
		}
		if !found {
			t.Errorf("sink %s not registered in C# catalog", id)
		}
	}
}
