// Cross-file STORED-STATE taint tests (Tier-1).
//
// These exercise WalkCrossFileStoredState: a method that writes external
// taint into an instance field in one file, joined by enclosing class
// identity to a method in ANOTHER file that reads the same field into a
// sink. This flow has no call edge between the two methods, so the
// call-edge-driven cross-file walk (WalkCrossFileTaintFlows) cannot see it.

package graph

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// hasStoredStateFinding reports whether any finding is the cross-file
// stored-state class (tagged "stored-state") for the given sink-bearing
// field name appearing in the title.
func hasStoredStateFinding(findings []rules.Finding, fieldNeedle string) bool {
	for _, f := range findings {
		isStored := false
		for _, tag := range f.Tags {
			if tag == "stored-state" {
				isStored = true
				break
			}
		}
		if isStored && strings.Contains(f.Title, fieldNeedle) {
			return true
		}
	}
	return false
}

// TestCrossFileStoredState_FieldWriteReadAcrossFiles is the positive case:
// class UserController is split across two files; one method stores
// request input into self.user_query, a method in the OTHER file reads it
// into os.system. The flow must be surfaced.
func TestCrossFileStoredState_FieldWriteReadAcrossFiles(t *testing.T) {
	cg, _ := pythonScanFixture(t, map[string]string{
		"store.py": `import flask


class UserController:
    def load(self):
        self.user_query = flask.request.args.get("q")
`,
		"use.py": `import os


class UserController:
    def run(self):
        os.system(self.user_query)
`,
	})

	findings := WalkCrossFileStoredState(cg)
	if !hasStoredStateFinding(findings, "user_query") {
		t.Fatalf("expected a cross-file stored-state finding for self.user_query, got %d findings: %+v", len(findings), findings)
	}
	// The taint path must span the two files: source in store.py, sink in use.py.
	var found rules.Finding
	for _, f := range findings {
		if strings.Contains(f.Title, "user_query") {
			found = f
			break
		}
	}
	if len(found.TaintPath) < 2 {
		t.Fatalf("expected a two-step taint path, got %+v", found.TaintPath)
	}
	src := found.TaintPath[0]
	sink := found.TaintPath[len(found.TaintPath)-1]
	if !strings.HasSuffix(src.File, "store.py") {
		t.Errorf("expected source step in store.py, got %s", src.File)
	}
	if !strings.HasSuffix(sink.File, "use.py") {
		t.Errorf("expected sink step in use.py, got %s", sink.File)
	}
	if found.ConfidenceScore != 0.8 {
		t.Errorf("expected confidence 0.8, got %v", found.ConfidenceScore)
	}
}

// TestCrossFileStoredState_SameFileNotEmitted guards against double-firing:
// when the write and the read live in the SAME file, this pass must stay
// silent (the per-file tsflow stored-state channel already covers it).
func TestCrossFileStoredState_SameFileNotEmitted(t *testing.T) {
	cg, _ := pythonScanFixture(t, map[string]string{
		"single.py": `import os
import flask


class UserController:
    def load(self):
        self.user_query = flask.request.args.get("q")

    def run(self):
        os.system(self.user_query)
`,
	})

	findings := WalkCrossFileStoredState(cg)
	if hasStoredStateFinding(findings, "user_query") {
		t.Fatalf("same-file write+read must NOT emit a cross-file stored-state finding, got %+v", findings)
	}
}

// TestCrossFileStoredState_ParamSourceNotEmitted guards FP discipline: a
// field written from a method PARAMETER (the caller's value, already
// modelled by param->return) is not a stored external source, so no
// stored-state finding fires even across files.
func TestCrossFileStoredState_ParamSourceNotEmitted(t *testing.T) {
	cg, _ := pythonScanFixture(t, map[string]string{
		"store.py": `class UserController:
    def load(self, data):
        self.user_query = data
`,
		"use.py": `import os


class UserController:
    def run(self):
        os.system(self.user_query)
`,
	})

	findings := WalkCrossFileStoredState(cg)
	if hasStoredStateFinding(findings, "user_query") {
		t.Fatalf("field written from a parameter must NOT emit a stored-state finding, got %+v", findings)
	}
}

// TestCrossFileStoredState_DistinctClassNotJoined guards the class-identity
// join: a field written in class A and read in class B (different classes,
// different files) must NOT connect — the field key is class-scoped.
func TestCrossFileStoredState_DistinctClassNotJoined(t *testing.T) {
	cg, _ := pythonScanFixture(t, map[string]string{
		"store.py": `import flask


class Writer:
    def load(self):
        self.user_query = flask.request.args.get("q")
`,
		"use.py": `import os


class Reader:
    def run(self):
        os.system(self.user_query)
`,
	})

	findings := WalkCrossFileStoredState(cg)
	if hasStoredStateFinding(findings, "user_query") {
		t.Fatalf("distinct classes must NOT be joined by field name, got %+v", findings)
	}
}

// TestCrossFileStoredState_EntityLookupNotEmitted guards the entity-lookup
// gate on the Python path: a Django ORM lookup keyed by request input stores
// a model OBJECT, not the raw external value, so no stored-state source.
func TestCrossFileStoredState_EntityLookupNotEmitted(t *testing.T) {
	cg, _ := pythonScanFixture(t, map[string]string{
		"store.py": `import flask


class UserController:
    def load(self):
        self.user_query = User.objects.get(pk=flask.request.args.get("q"))
`,
		"use.py": `import os


class UserController:
    def run(self):
        os.system(self.user_query)
`,
	})

	findings := WalkCrossFileStoredState(cg)
	if hasStoredStateFinding(findings, "user_query") {
		t.Fatalf("ORM entity lookup must NOT be a stored external source, got %+v", findings)
	}
}

// TestCrossFileStoredState_SanitizedWriteNotEmitted guards that a sanitized
// write is not treated as a stored external source.
func TestCrossFileStoredState_SanitizedWriteNotEmitted(t *testing.T) {
	cg, _ := pythonScanFixture(t, map[string]string{
		"store.py": `import flask
import shlex


class UserController:
    def load(self):
        self.user_query = shlex.quote(flask.request.args.get("q"))
`,
		"use.py": `import os


class UserController:
    def run(self):
        os.system(self.user_query)
`,
	})

	findings := WalkCrossFileStoredState(cg)
	if hasStoredStateFinding(findings, "user_query") {
		t.Fatalf("sanitized write must NOT emit a stored-state finding, got %+v", findings)
	}
}
