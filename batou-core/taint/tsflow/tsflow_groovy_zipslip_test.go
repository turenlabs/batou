package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Groovy archive-extraction / Zip Slip sinks (CWE-22) added to
// groovy_sinks.go.
//
// Groovy is a JVM language and extracts archives through three idiomatic
// routes: the zip4j library (net.lingala.zip4j.ZipFile — ctor/extractAll/
// extractFile), and the built-in groovy.util.AntBuilder unzip/untar/expand
// tasks (driven via the `ant` receiver with named-argument maps). Extracting
// an attacker-supplied archive without validating entry names lets a crafted
// entry ("../../etc/...") escape the destination directory — the Zip Slip
// vulnerability that is endemic to the JVM ecosystem.
//
// Catalog entries land at receiver "zipFile" (matched to ObjectType
// "net.lingala.zip4j.ZipFile" — last component "zipfile") and "ant"/
// "antBuilder" (matched to ObjectType "AntBuilder" via tsflow's
// prefix-abbreviation heuristic). The taint source is the Spring WebFlux
// ServerRequest.queryParam already recognised by groovy_sources.go.

func TestGroovy_Zip4jExtractAllZipSlip(t *testing.T) {
	code := `
def handle(request) {
    def dest = request.queryParam("dest")
    zipFile.extractAll(dest)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow for queryParam -> zip4j ZipFile.extractAll")
		dumpZipFlows(t, flows)
	}
}

func TestGroovy_Zip4jExtractFileZipSlip(t *testing.T) {
	code := `
def handle(request) {
    def dest = request.queryParam("dest")
    zipFile.extractFile(header, dest)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow for queryParam -> zip4j ZipFile.extractFile")
		dumpZipFlows(t, flows)
	}
}

func TestGroovy_Zip4jCtorPathInjection(t *testing.T) {
	code := `
def handle(request) {
    def archive = request.queryParam("zip")
    def zf = new ZipFile(archive)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected path-injection flow for queryParam -> new ZipFile(archive)")
		dumpZipFlows(t, flows)
	}
}

func TestGroovy_AntUnzipZipSlip(t *testing.T) {
	code := `
def handle(request) {
    def src = request.queryParam("src")
    ant.unzip(src: src, dest: "/out")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow for queryParam -> AntBuilder ant.unzip")
		dumpZipFlows(t, flows)
	}
}

func TestGroovy_AntUntarZipSlip(t *testing.T) {
	code := `
def handle(request) {
    def src = request.queryParam("src")
    ant.untar(src: src, dest: "/out")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow for queryParam -> AntBuilder ant.untar")
		dumpZipFlows(t, flows)
	}
}

func TestGroovy_AntExpandZipSlip(t *testing.T) {
	code := `
def handle(request) {
    def src = request.queryParam("src")
    ant.expand(src: src, dest: "/out")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected Zip Slip flow for queryParam -> AntBuilder ant.expand")
		dumpZipFlows(t, flows)
	}
}

// Negative control: a hardcoded constant archive path must NOT raise a flow.
func TestGroovy_ZipSlipNoFlowOnConstant(t *testing.T) {
	code := `
def handle(request) {
    zipFile.extractAll("/srv/releases/build.zip")
    ant.unzip(src: "/srv/releases/build.zip", dest: "/out")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("did not expect a Zip Slip flow for a constant archive path")
		dumpZipFlows(t, flows)
	}
}

func dumpZipFlows(t *testing.T, flows []taint.TaintFlow) {
	t.Helper()
	for _, f := range flows {
		t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
	}
}
