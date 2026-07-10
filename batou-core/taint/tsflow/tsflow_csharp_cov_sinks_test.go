package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# coverage-expansion taint sinks (CWE-502 deserialization, CWE-780 RSA).
//
// These verify the new ObjectType-anchored sinks added in csharp_sinks.go fire
// when a request-controlled value reaches them, and that the OAEP sanitizer
// keeps the RSA padding-oracle sink clean.
// ===========================================================================

// --- FsPickler.Deserialize<T> (CWE-502) ---

func TestCSharp_Sink_FsPickler_Deserialize(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using MBrace.FsPickler;

public class StateController : Controller {
    public IActionResult Restore() {
        var stream = Request.Body;
        var pickler = FsPickler.CreateBinarySerializer();
        var state = pickler.Deserialize<AppState>(stream);
        return Ok(state);
    }
}
`
	flows := Analyze(code, "/app/StateController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for FsPickler.Deserialize<T>")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- fastJSON.JSON.ToObject (CWE-502) ---

func TestCSharp_Sink_FastJSON_ToObject(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;

public class ApiController : Controller {
    public IActionResult Parse() {
        var body = Request.Body;
        var obj = fastJSON.JSON.ToObject<Widget>(body);
        return Ok(obj);
    }
}
`
	flows := Analyze(code, "/app/ApiController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected SnkDeserialize flow for fastJSON.JSON.ToObject")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ===========================================================================
// ECL wave-2: XSLT injection (CWE-91), DataSet/DataTable ReadXml and
// YamlDotNet deserialization (CWE-502). Each verifies the new sink fires on a
// request-controlled value AND stays clean on a constant/trusted value.
// ===========================================================================

// --- DataSet/DataTable.ReadXml (CWE-502) ---

func TestCSharp_Sink_DataSet_ReadXml(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using System.Data;

public class ImportController : Controller {
    public IActionResult Import() {
        var body = Request.Body;
        var ds = new DataSet();
        ds.ReadXml(body);
        return Ok(ds);
    }
}
`
	flows := Analyze(code, "/app/ImportController.cs", rules.LangCSharp)
	if !hasTaintFlowCWE(flows, "CWE-502") {
		t.Error("expected CWE-502 flow for DataSet.ReadXml(tainted)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestCSharp_Sink_DataTable_ReadXml(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using System.Data;

public class ImportController : Controller {
    public IActionResult Import() {
        string xml = Request.Form;
        var dt = new DataTable();
        dt.ReadXml(xml);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ImportController.cs", rules.LangCSharp)
	if !hasTaintFlowCWE(flows, "CWE-502") {
		t.Error("expected CWE-502 flow for DataTable.ReadXml(tainted)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestCSharp_Sink_DataSet_ReadXml_ConstantSafe(t *testing.T) {
	// Reading a bundled, application-controlled XML file is not attacker input.
	code := `
using System.Data;

public class Loader {
    public DataSet Load() {
        var ds = new DataSet();
        ds.ReadXml("config/seed-data.xml");
        return ds;
    }
}
`
	flows := Analyze(code, "/app/Loader.cs", rules.LangCSharp)
	if hasTaintFlowCWE(flows, "CWE-502") {
		t.Error("did NOT expect a flow for ReadXml of a constant path")
	}
}

// --- ServiceStack.Text DeserializeFromString<T> (CWE-502) ---

func TestCSharp_Sink_ServiceStack_DeserializeFromString(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using ServiceStack.Text;

public class ImportController : Controller {
    public IActionResult Apply() {
        var body = Request.Body;
        var dto = TypeSerializer.DeserializeFromString<object>(body);
        return Ok(dto);
    }
}
`
	flows := Analyze(code, "/app/ImportController.cs", rules.LangCSharp)
	if !hasTaintFlowCWE(flows, "CWE-502") {
		t.Error("expected CWE-502 flow for ServiceStack TypeSerializer.DeserializeFromString(tainted)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestCSharp_Sink_ServiceStack_ConstantSafe(t *testing.T) {
	// Deserializing an application-controlled constant is not attacker input.
	code := `
using ServiceStack.Text;

public class Loader {
    public Config Load() {
        return TypeSerializer.DeserializeFromString<Config>("{\"name\":\"default\"}");
    }
}
`
	flows := Analyze(code, "/app/Loader.cs", rules.LangCSharp)
	if hasTaintFlowCWE(flows, "CWE-502") {
		t.Error("did NOT expect a flow for DeserializeFromString of a constant string")
	}
}

// --- XSLT injection: XslCompiledTransform.Load (CWE-91) ---

func TestCSharp_Sink_Xslt_Load(t *testing.T) {
	code := `
using Microsoft.AspNetCore.Mvc;
using System.Xml.Xsl;

public class ReportController : Controller {
    public IActionResult Render() {
        var sheet = Request.Body;
        var xslt = new XslCompiledTransform();
        xslt.Load(sheet);
        return Ok();
    }
}
`
	flows := Analyze(code, "/app/ReportController.cs", rules.LangCSharp)
	if !hasTaintFlowCWE(flows, "CWE-91") {
		t.Error("expected CWE-91 flow for XslCompiledTransform.Load(tainted)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (%s)", f.Source.Category, f.Sink.Category, f.Sink.CWEID)
		}
	}
}

func TestCSharp_Sink_Xslt_ConstantSafe(t *testing.T) {
	// Loading an application-bundled stylesheet by a constant path is safe.
	code := `
using System.Xml.Xsl;

public class Renderer {
    public void Setup() {
        var xslt = new XslCompiledTransform();
        xslt.Load("templates/report.xslt");
    }
}
`
	flows := Analyze(code, "/app/Renderer.cs", rules.LangCSharp)
	if hasTaintFlowCWE(flows, "CWE-91") {
		t.Error("did NOT expect a flow for XslCompiledTransform.Load of a constant path")
	}
}
