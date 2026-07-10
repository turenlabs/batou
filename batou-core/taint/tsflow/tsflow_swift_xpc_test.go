package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — XPC inter-process message sources
// =========================================================================
//
// Apple's libxpc (<xpc/xpc.h>) is the canonical macOS/iOS IPC primitive used by
// privileged helper tools (SMJobBless), launchd daemons, XPC services, and app
// extensions. The receiving process treats incoming xpc_object_t messages as
// untrusted input from another (potentially non-privileged) process; even after
// audit_token validation the payload contents remain attacker-controlled.
//
// Real-world CVE pattern: xpc_dictionary_get_string flows directly to system(),
// dlopen(), Process.run, NSAppleScript, sqlite3_exec, etc. (CVE-2020-9839,
// CVE-2019-8500, CVE-2021-30724, etc.).
//
// The xpc_dictionary_get_* / xpc_array_get_* / xpc_*_get_* functions are free
// C functions imported into Swift via the XPC framework, so ObjectType "" +
// the unique xpc_-prefixed name fully scopes the source.

// xpc_dictionary_get_string -> system() — classic privileged-helper RCE.
func TestSwift_XPC_DictionaryString_ToSystem(t *testing.T) {
	code := `
import XPC

func handlePeerEvent(event: xpc_object_t) {
    let cmdPtr = xpc_dictionary_get_string(event, "command")
    system(cmdPtr)
}
`
	flows := Analyze(code, "/app/HelperTool.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for xpc_dictionary_get_string -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xpc_dictionary_get_string -> popen() — pipe-to-shell RCE pattern.
func TestSwift_XPC_DictionaryString_ToPopen(t *testing.T) {
	code := `
import XPC

func handlePeerEvent(event: xpc_object_t) {
    let cmdPtr = xpc_dictionary_get_string(event, "cmd")
    let _ = popen(cmdPtr, "r")
}
`
	flows := Analyze(code, "/app/HelperTool.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for xpc_dictionary_get_string -> popen()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xpc_dictionary_get_string -> NSAppleScript(source:) — AppleScript injection
// in privileged GUI helpers (CVE-2018-4296 family).
func TestSwift_XPC_DictionaryString_ToAppleScript(t *testing.T) {
	code := `
import Foundation
import XPC

func handlePeerEvent(event: xpc_object_t) {
    let scriptPtr = xpc_dictionary_get_string(event, "script")
    let script = NSAppleScript(source: scriptPtr)
    _ = script
}
`
	flows := Analyze(code, "/app/PrivHelper.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for xpc_dictionary_get_string -> NSAppleScript(source:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xpc_dictionary_get_value + xpc_string_get_string_ptr -> system() — generic
// xpc_object_t routing through the type-conversion accessor.
func TestSwift_XPC_GenericValue_StringPtr_ToSystem(t *testing.T) {
	code := `
import XPC

func handlePeerEvent(event: xpc_object_t) {
    let value = xpc_dictionary_get_value(event, "command")
    let strPtr = xpc_string_get_string_ptr(value)
    system(strPtr)
}
`
	flows := Analyze(code, "/app/HelperTool.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for xpc_dictionary_get_value -> xpc_string_get_string_ptr -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xpc_dictionary_get_string interpolated into a SQL string -> sqlite3_exec().
// SQL injection in a privileged helper that stores attacker-supplied strings.
func TestSwift_XPC_DictionaryString_ToSQLExec(t *testing.T) {
	code := `
import SQLite3
import XPC

func handlePeerEvent(event: xpc_object_t, db: OpaquePointer?) {
    let namePtr = xpc_dictionary_get_string(event, "name")
    let sql = "INSERT INTO events (name) VALUES ('" + namePtr + "')"
    sqlite3_exec(db, sql, nil, nil, nil)
}
`
	flows := Analyze(code, "/app/PrivHelper.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow for xpc_dictionary_get_string -> sqlite3_exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xpc_array_get_string element -> system() — array-of-args style XPC payload.
func TestSwift_XPC_ArrayString_ToSystem(t *testing.T) {
	code := `
import XPC

func handlePeerEvent(event: xpc_object_t) {
    let args = xpc_dictionary_get_array(event, "args")
    let firstPtr = xpc_array_get_string(args, 0)
    system(firstPtr)
}
`
	flows := Analyze(code, "/app/HelperTool.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for xpc_array_get_string -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xpc_dictionary_get_dictionary -> nested xpc_dictionary_get_string -> system().
// Verifies taint propagates through nested-dictionary extraction.
func TestSwift_XPC_NestedDictionary_ToSystem(t *testing.T) {
	code := `
import XPC

func handlePeerEvent(event: xpc_object_t) {
    let payload = xpc_dictionary_get_dictionary(event, "payload")
    let cmdPtr = xpc_dictionary_get_string(payload, "command")
    system(cmdPtr)
}
`
	flows := Analyze(code, "/app/HelperTool.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected SnkCommand flow for nested xpc_dictionary_get_dictionary -> get_string -> system()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative test: hardcoded constant string -> system(). No XPC source involved,
// no flow expected. Guards against pattern over-broadness regression.
func TestSwift_XPC_HardcodedString_ToSystem_Safe(t *testing.T) {
	code := `
import Foundation

func setup() {
    let cmd = "/usr/bin/true"
    system(cmd)
}
`
	flows := Analyze(code, "/app/Setup.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Source.ID != "" &&
			(f.Source.ID == "swift.xpc.dictionary.string" ||
				f.Source.ID == "swift.xpc.dictionary.value" ||
				f.Source.ID == "swift.xpc.string.value" ||
				f.Source.ID == "swift.xpc.array.string" ||
				f.Source.ID == "swift.xpc.dictionary.array" ||
				f.Source.ID == "swift.xpc.dictionary.dictionary") {
			t.Errorf("unexpected XPC source flow on hardcoded string: source=%s sink=%s", f.Source.ID, f.Sink.ID)
		}
	}
}
