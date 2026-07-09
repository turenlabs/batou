package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Swift — MySQLNIO SQL injection tests
// =========================================================================

func TestSwift_MySQLNIO_SimpleQuery_SQLInjection(t *testing.T) {
	code := `
import MySQLNIO
import Vapor

func handler(req: Request) {
    let name = req.query["name"]
    req.mysql.simpleQuery("SELECT * FROM users WHERE name = '\(name)'")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for req.query -> simpleQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_MySQLNIO_SimpleQuery_Sanitized_Bindings(t *testing.T) {
	code := `
import MySQLNIO
import Vapor

func handler(req: Request) {
    let name = req.query["name"]
    req.mysql.query("SELECT * FROM users WHERE name = ?", [MySQLData(string: name)])
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when parameterized query with bindings is used")
		}
	}
}

// =========================================================================
// Swift — Vapor FileIO path traversal tests
// =========================================================================

func TestSwift_VaporFileIO_StreamFile_PathTraversal(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) -> Response {
    let filename = req.query["filename"]
    let path = "/uploads/" + filename
    return req.fileio.streamFile(at: path)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for req.query -> fileio.streamFile(at:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_VaporFileIO_CollectFile_PathTraversal(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) -> ByteBuffer {
    let filename = req.query["file"]
    let path = "/uploads/" + filename
    return req.fileio.collectFile(at: path)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for req.query -> fileio.collectFile(at:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_VaporFileIO_ReadFile_PathTraversal(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) -> String {
    let name = req.query["name"]
    return req.fileio.readFile(at: "/data/" + name)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for parameter name -> fileio.readFile(at:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_VaporFileIO_WriteFile_PathTraversal(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) {
    let filename = req.query["name"]
    let data = ByteBuffer(string: "content")
    req.fileio.writeFile(data, at: "/uploads/" + filename)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for req.query -> fileio.writeFile(at:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_VaporFileIO_Sanitized_LastPathComponent(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) -> Response {
    let filename = req.query["filename"]
    let safeName = URL(fileURLWithPath: filename).lastPathComponent
    let path = "/uploads/" + safeName
    return req.fileio.streamFile(at: path)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO file read flow when lastPathComponent sanitizes the path")
		}
	}
}

// =========================================================================
// Swift — Database source (second-order injection) tests
// =========================================================================

func TestSwift_SQLite3_Column_To_SQLQuery(t *testing.T) {
	// Direct assignment from sqlite3_column_text (no String wrapper)
	code := `
import Foundation

func handler(db: OpaquePointer, stmt: OpaquePointer) {
    let name = sqlite3_column_text(stmt, 0)
    sqlite3_exec(db, "SELECT * FROM orders WHERE customer = '" + name + "'", nil, nil, nil)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for sqlite3_column_text -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_GRDB_Row_Fetch_To_SQLQuery(t *testing.T) {
	code := `
import GRDB

func handler(db: OpaquePointer) {
    let rows = Row.fetchAll(db, sql: "SELECT name FROM users")
    let name = rows.first
    sqlite3_exec(db, "INSERT INTO log VALUES ('" + name + "')", nil, nil, nil)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for GRDB Row.fetchAll -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_Fluent_Query_To_SQLQuery(t *testing.T) {
	code := `
import Vapor
import Fluent

func handler(req: Request, db: OpaquePointer) {
    let users = User.query(on: req.db)
    let name = users.first
    sqlite3_exec(db, "SELECT * FROM log WHERE user = '" + name + "'", nil, nil, nil)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Fluent query -> sqlite3_exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_Realm_Objects_To_Eval(t *testing.T) {
	code := `
import RealmSwift
import WebKit

func handler(realm: Realm) {
    let configs = realm.objects(Config.self)
    let script = configs.first
    wkWebView.evaluateJavaScript(script)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for Realm objects -> evaluateJavaScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Swift — LDAP injection tests
// =========================================================================

func TestSwift_PerfectLDAP_Search_Injection(t *testing.T) {
	code := `
import PerfectLDAP
import Vapor

func handler(req: Request) {
    let username = req.query["username"]
    ldap.search(base: "dc=example,dc=com", filter: "(uid=" + username + ")")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for req.query -> ldap.search(base:filter:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_OpenDirectory_ODQuery_Injection(t *testing.T) {
	code := `
import OpenDirectory
import Vapor

func handler(req: Request) {
    let name = req.query["name"]
    ODQuery(node: node, forRecordTypes: kODRecordTypeUsers, attribute: kODAttributeTypeRecordName, matchType: ODMatchType(kODMatchContains), queryValues: name, returnAttributes: kODAttributeTypeNativeOnly, maximumResults: 0)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for req.query -> ODQuery(node:)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_LibLDAP_Search_Injection(t *testing.T) {
	code := `
import Vapor

func handler(req: Request) {
    let filter = req.query["filter"]
    ldap_search_ext_s(ldap, "dc=example,dc=com", LDAP_SCOPE_SUBTREE, filter, nil, 0, nil, nil, nil, 0, nil)
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected LDAP injection flow for req.query -> ldap_search_ext_s")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestSwift_LDAP_Sanitized_FilterEscape(t *testing.T) {
	code := `
import PerfectLDAP
import Vapor

func handler(req: Request) {
    let username = req.query["username"]
    let safe = username.replacingOccurrences(of: "(", with: "\\28")
    ldap.search(base: "dc=example,dc=com", filter: "(uid=" + safe + ")")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP injection flow when LDAP filter characters are escaped")
		}
	}
}
