package astflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Catalog registration tests ---
// Verify new deserialized and file-read source entries are indexed in the CatalogMatcher.

func TestCatalogMatcher_DeserializedSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	expectedMethods := []string{
		"NewDecoder", // json.NewDecoder, xml.NewDecoder, yaml.NewDecoder, gob.NewDecoder
		"Unmarshal",  // json.Unmarshal, xml.Unmarshal, yaml.Unmarshal, msgpack.Unmarshal, proto.Unmarshal, toml.Unmarshal
		"Decode",     // toml.Decode
	}

	for _, method := range expectedMethods {
		found := false
		for _, src := range matcher.sourcesByMethod[method] {
			if src.Category == taint.SrcDeserialized {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be indexed as SrcDeserialized source", method)
		}
	}
}

func TestCatalogMatcher_FileReadSourcesRegistered(t *testing.T) {
	cat := taint.GetCatalog("go")
	if cat == nil {
		t.Fatal("Go catalog not registered")
	}

	sources := cat.Sources()
	matcher := NewCatalogMatcher(sources, nil, nil, nil)

	// Check ReadFile is indexed for both os and ioutil
	readFileEntries := matcher.sourcesByMethod["ReadFile"]
	foundOS := false
	foundIoutil := false
	for _, src := range readFileEntries {
		if src.Category == taint.SrcFileRead {
			if src.ID == "go.os.readfile" {
				foundOS = true
			}
			if src.ID == "go.ioutil.readfile" {
				foundIoutil = true
			}
		}
	}
	if !foundOS {
		t.Error("expected go.os.readfile to be indexed as SrcFileRead")
	}
	if !foundIoutil {
		t.Error("expected go.ioutil.readfile to be indexed as SrcFileRead")
	}

	// Check ReadAll is indexed for ioutil
	readAllEntries := matcher.sourcesByMethod["ReadAll"]
	foundIoutilReadAll := false
	for _, src := range readAllEntries {
		if src.ID == "go.ioutil.readall" {
			foundIoutilReadAll = true
			break
		}
	}
	if !foundIoutilReadAll {
		t.Error("expected go.ioutil.readall to be indexed as SrcFileRead")
	}
}

// --- End-to-end flow tests ---
// These test taint flows from deserialized data into dangerous sinks.

func TestAnalyzeGo_JSONUnmarshal_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"encoding/json"
)

func handler(db *sql.DB, data []byte) {
	config := json.Unmarshal(data, nil)
	db.Query("SELECT * FROM logs WHERE config = '" + config + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: json.Unmarshal → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_XMLUnmarshal_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"encoding/xml"
)

func handler(db *sql.DB, data []byte) {
	config := xml.Unmarshal(data, nil)
	db.Query("SELECT * FROM logs WHERE config = '" + config + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: xml.Unmarshal → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_YAMLUnmarshal_CommandInjection(t *testing.T) {
	code := `package main

import (
	"os/exec"
	"gopkg.in/yaml.v3"
)

func handler(data []byte) {
	config := yaml.Unmarshal(data, nil)
	exec.Command(config)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection: yaml.Unmarshal → exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_GobDecoder_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"encoding/gob"
	"bytes"
)

func handler(db *sql.DB, data []byte) {
	dec := gob.NewDecoder(bytes.NewReader(data))
	db.Query("SELECT * FROM logs WHERE dec = '" + dec + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: gob.NewDecoder → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_ProtoUnmarshal_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"google.golang.org/protobuf/proto"
)

func handler(db *sql.DB, data []byte) {
	msg := proto.Unmarshal(data, nil)
	db.Query("SELECT * FROM logs WHERE msg = '" + msg + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: proto.Unmarshal → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_TOMLDecode_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/BurntSushi/toml"
)

func handler(db *sql.DB, data string) {
	config := toml.Decode(data, nil)
	db.Query("SELECT * FROM logs WHERE config = '" + config + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: toml.Decode → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_XMLNewDecoder_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"encoding/xml"
	"strings"
)

func handler(db *sql.DB, data string) {
	dec := xml.NewDecoder(strings.NewReader(data))
	db.Query("SELECT * FROM logs WHERE dec = '" + dec + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: xml.NewDecoder → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}

func TestAnalyzeGo_IoutilReadFile_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"io/ioutil"
)

func handler(db *sql.DB, path string) {
	data := ioutil.ReadFile(path)
	db.Query("SELECT * FROM logs WHERE data = '" + data + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: ioutil.ReadFile → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcFileRead) {
		t.Error("expected source category to be SrcFileRead")
	}
}

func TestAnalyzeGo_IoutilReadAll_CommandInjection(t *testing.T) {
	code := `package main

import (
	"os/exec"
	"io/ioutil"
	"os"
)

func handler() {
	f, _ := os.Open("config.txt")
	data := ioutil.ReadAll(f)
	exec.Command(data)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection: ioutil.ReadAll → exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	// ioutil.ReadAll reads from any io.Reader (file, network, etc.)
	// so the source category may be SrcNetwork (from go.io.readall) or SrcFileRead
	if !hasSourceCategory(flows, taint.SrcNetwork) && !hasSourceCategory(flows, taint.SrcFileRead) {
		t.Error("expected source category to be SrcNetwork or SrcFileRead")
	}
}

func TestAnalyzeGo_MsgpackUnmarshal_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"github.com/vmihailenco/msgpack"
)

func handler(db *sql.DB, data []byte) {
	config := msgpack.Unmarshal(data, nil)
	db.Query("SELECT * FROM logs WHERE config = '" + config + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection: msgpack.Unmarshal → db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
	if !hasSourceCategory(flows, taint.SrcDeserialized) {
		t.Error("expected source category to be SrcDeserialized")
	}
}
