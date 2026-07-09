package tsflow

import (
	"fmt"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Swift — fixed-width & unsigned integer / wide-float coercion sanitizers
// (swift.int8.init .. swift.float64.init). A failable numeric initializer
// constrains user input to a provably-numeric value, neutralizing SQL /
// command / path / NoSQL / LDAP / XPath injection.
// =========================================================================

// Control: the tainted query param flows straight into a SQL sink.
func TestSwift_NumericCoercion_Control_SQLInjection(t *testing.T) {
	code := `
import MySQLNIO
import Vapor

func handler(req: Request) {
    let raw = req.query["id"]
    req.mysql.simpleQuery("SELECT * FROM users WHERE id = \(raw)")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Fatal("control: expected SQL injection flow for unsanitized req.query -> simpleQuery")
	}
}

// Each fixed-width / unsigned / wide-float initializer must neutralize the
// SQL flow when the tainted value is coerced before interpolation.
func TestSwift_NumericCoercion_SQL_Sanitized(t *testing.T) {
	types := []string{
		"Int8", "Int16", "Int32", "Int64",
		"UInt", "UInt8", "UInt16", "UInt32", "UInt64",
		"Float32", "Float64",
	}
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			code := fmt.Sprintf(`
import MySQLNIO
import Vapor

func handler(req: Request) {
    let raw = req.query["id"]
    let id = %s(raw)
    req.mysql.simpleQuery("SELECT * FROM users WHERE id = \(id)")
}
`, typ)
			flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
			for _, f := range flows {
				if f.Sink.Category == taint.SnkSQLQuery {
					t.Errorf("%s(raw) should neutralize SQL injection, but a SnkSQLQuery flow was reported (conf %.2f)", typ, f.Confidence)
				}
			}
		})
	}
}

// Second category — command injection (CWE-78): the Neutralizes set spans
// more than SQL, so confirm coercion also blocks a command-exec sink.
func TestSwift_NumericCoercion_Command_Control(t *testing.T) {
	code := `
import Foundation

func handler(req: Request) {
    let raw = req.query["n"]
    system("echo \(raw)")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Fatal("control: expected command-injection flow for unsanitized req.query -> system()")
	}
}

func TestSwift_NumericCoercion_Command_Sanitized(t *testing.T) {
	code := `
import Foundation

func handler(req: Request) {
    let raw = req.query["n"]
    let n = Int64(raw)
    system("echo \(n)")
}
`
	flows := Analyze(code, "/app/handler.swift", rules.LangSwift)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Errorf("Int64(raw) should neutralize command injection, but a SnkCommand flow was reported (conf %.2f)", f.Confidence)
		}
	}
}
