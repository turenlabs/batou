package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	// Import taint languages catalog so Go sources/sinks are registered.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Config-derived file-read sources are NOT attacker input.
//
// Real-world smoke test (Grafana) surfaced false positives where the
// application's OWN operator config / build artifacts were treated as
// untrusted taint sources:
//
//	bootScriptRaw, _ := os.ReadFile(filepath.Join(cfg.StaticRootPath, "build", "boot.js"))
//	... template.JS(bootScriptRaw)            // FP: file_read -> template_render
//
//	certPEMBlock, _ := os.ReadFile(s.ClientCertFilePath)  // FP: config path
//
// The operator chooses these paths, not a request, so the file read is an
// internal source and must not seed taint. These tests pin the FP shapes as
// CLEAN, plus a matching true-positive (a request-derived path) that must
// STILL fire — proving the gate is tightened, not disabled.
// =========================================================================

// fileReadSeedsTaint reports whether any flow in the slice was rooted at a
// file_read source. A gated (internal) read produces no such flow.
func fileReadSeedsTaint(flows []taint.TaintFlow) bool {
	return hasSourceCategory(flows, taint.SrcFileRead)
}

func TestAnalyzeGo_ConfigFileRead_StaticRootPathBuildArtifact_NotASource(t *testing.T) {
	// The boot.js shape: os.ReadFile(filepath.Join(cfg.StaticRootPath, "build", "boot.js")).
	code := `package main

import (
	"html/template"
	"os"
	"path/filepath"
)

type Cfg struct{ StaticRootPath string }

func render(cfg *Cfg) template.JS {
	bootScriptRaw, _ := os.ReadFile(filepath.Join(cfg.StaticRootPath, "build", "boot.js"))
	return template.JS(bootScriptRaw)
}
`
	flows := AnalyzeGo(code, "/app/frontend/index.go")
	if fileReadSeedsTaint(flows) {
		t.Errorf("config build-artifact read os.ReadFile(filepath.Join(cfg.StaticRootPath, ...)) must NOT seed a file_read taint source")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s (%s) -> %s", f.Source.ID, f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_ConfigFileRead_StructFilePathField_NotASource(t *testing.T) {
	// The TLS-config shape: os.ReadFile(s.ClientCertFilePath) — the field name
	// suffix (FilePath) marks an operator-configured path.
	code := `package main

import "os"

type proxySettings struct {
	ClientCertFilePath string
	ClientKeyFilePath  string
}

func loadCert(s *proxySettings) {
	certPEMBlock, _ := os.ReadFile(s.ClientCertFilePath)
	keyPEMBlock, _ := os.ReadFile(s.ClientKeyFilePath)
	_ = certPEMBlock
	_ = keyPEMBlock
}
`
	flows := AnalyzeGo(code, "/app/setting/proxy.go")
	if fileReadSeedsTaint(flows) {
		t.Errorf("config struct field read os.ReadFile(s.ClientCertFilePath) must NOT seed a file_read taint source")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s (%s) -> %s", f.Source.ID, f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_ConfigFileRead_NestedCfgChain_NotASource(t *testing.T) {
	// os.ReadFile(s.Cfg.JWTAuth.TlsClientCa): a Cfg-typed intermediate field.
	code := `package main

import "os"

type jwtAuth struct{ TlsClientCa string }
type appCfg struct{ JWTAuth jwtAuth }
type svc struct{ Cfg *appCfg }

func loadCA(s *svc) {
	caCert, _ := os.ReadFile(s.Cfg.JWTAuth.TlsClientCa)
	_ = caCert
}
`
	flows := AnalyzeGo(code, "/app/auth/jwt/keys.go")
	if fileReadSeedsTaint(flows) {
		t.Errorf("config chain read os.ReadFile(s.Cfg.JWTAuth.TlsClientCa) must NOT seed a file_read taint source")
	}
}

func TestAnalyzeGo_ConfigFileRead_LiteralPath_NotASource(t *testing.T) {
	// A constant string-literal path is not attacker-controlled.
	code := `package main

import "os"

func loadFixture() {
	body, _ := os.ReadFile("testdata/playlist.json")
	_ = body
}
`
	flows := AnalyzeGo(code, "/app/storage/doc.go")
	if fileReadSeedsTaint(flows) {
		t.Error("literal-path read os.ReadFile(\"testdata/playlist.json\") must NOT seed a file_read taint source")
	}
}

func TestAnalyzeGo_RequestDerivedFileRead_StillSeeds_TruePositive(t *testing.T) {
	// True positive that MUST still fire: the file path comes from the request,
	// and the file CONTENTS flow to an output sink (the same source category and
	// sink the config cases gate). Proves the gate is narrow.
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("tpl")
	body, _ := os.ReadFile(p)
	w.Write(body)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !fileReadSeedsTaint(flows) {
		t.Error("request-derived os.ReadFile(p) where p=r.FormValue(...) MUST still seed a file_read taint source (gate must not disable real path traversal)")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s", f.Source.ID, f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PlainVariableFileRead_StillSeeds(t *testing.T) {
	// A plain, non-config, non-literal variable path must still seed — the gate
	// only fires on positively-attributable config/constant shapes.
	code := `package main

import (
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	body, _ := os.ReadFile(name)
	w.Write(body)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !fileReadSeedsTaint(flows) {
		t.Error("os.ReadFile(name) with a request-derived plain variable MUST still seed a file_read source")
	}
}
