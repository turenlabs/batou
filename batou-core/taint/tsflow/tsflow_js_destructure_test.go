package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// JS/TS object & array destructuring of a user-controlled value.
//
// Before the processJSDestructure fix, the dominant modern Express/Node idiom
//   const { id } = req.params;   const { name } = req.body;
// produced ZERO taint flows: the shorthand `{id}` parses as a
// shorthand_property_identifier_pattern (not an `identifier`), so the single
// extractVarDeclParts path bound nothing and the declaration was a no-op.
// These tests pin the recall fix and its FP-safety.

func jsFlows(code string) []taint.TaintFlow {
	return Analyze(code, "/app/handler.js", rules.LangJavaScript)
}

func TestJSDestructure_ShorthandObject(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const { name } = req.query;
  cp.exec("ls " + name);
}`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for const {name} = req.query -> cp.exec")
	}
}

func TestJSDestructure_ReqBodyAndParams(t *testing.T) {
	for _, src := range []string{"req.body", "req.params"} {
		code := `
const cp = require('child_process');
function handler(req) {
  const { id } = ` + src + `;
  cp.exec("cat " + id);
}`
		if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
			t.Errorf("expected command_exec flow for const {id} = %s", src)
		}
	}
}

func TestJSDestructure_MultipleNames(t *testing.T) {
	// Sink consumes the SECOND destructured name — extractVarDeclParts only
	// ever returned the first identifier, so this case needs full binding.
	code := `
const cp = require('child_process');
function handler(req) {
  const { a, b } = req.query;
  cp.exec("echo " + b);
}`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for the 2nd destructured name b")
	}
}

func TestJSDestructure_RenamedPair(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const { q: alias } = req.query;
  cp.exec("ls " + alias);
}`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for renamed pair {q: alias}")
	}
}

func TestJSDestructure_WithDefault(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const { name = "guest" } = req.query;
  cp.exec("ls " + name);
}`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for {name = default}")
	}
}

func TestJSDestructure_ArrayPattern(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  const [first, second] = req.query.items;
  cp.exec("rm " + second);
}`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for array destructuring element")
	}
}

func TestJSDestructure_LetBinding(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  let { cmd } = req.body;
  cp.exec(cmd);
}`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for let {cmd} = req.body")
	}
}

func TestJSDestructure_InCallbackHandler(t *testing.T) {
	// The canonical Express route shape: destructure inside the (req,res) arrow.
	code := `
const cp = require('child_process');
app.post('/run', (req, res) => {
  const { cmd } = req.body;
  cp.exec(cmd);
});`
	if !hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("expected command_exec flow for destructure inside Express handler")
	}
}

func TestTSDestructure_Shorthand(t *testing.T) {
	code := `
import { exec } from 'child_process';
function handler(req: any) {
  const { name } = req.query;
  exec("ls " + name);
}`
	flows := Analyze(code, "/app/handler.ts", rules.LangTypeScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command_exec flow for TS const {name} = req.query")
	}
}

// FP-safety: destructuring a non-user-controlled object must NOT taint the
// bound locals.
func TestJSDestructure_SafeLiteral(t *testing.T) {
	code := `
const cp = require('child_process');
function handler() {
  const { name } = { name: "config.txt" };
  cp.exec("cat " + name);
}`
	if hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("false positive: destructuring a literal object must not taint")
	}
}

// FP-safety: a fresh destructuring declaration must SHADOW any prior tainted
// binding of the same name (last-write-wins on an untainted RHS).
func TestJSDestructure_ShadowsPriorTaint(t *testing.T) {
	code := `
const cp = require('child_process');
function handler(req) {
  let name = req.query.evil;
  ({ name } = { name: "safe.txt" });
  const { name: fresh } = { name: "also-safe.txt" };
  cp.exec("cat " + fresh);
}`
	if hasTaintFlow(jsFlows(code), taint.SnkCommand) {
		t.Error("false positive: fresh destructure from a literal must not carry prior taint")
	}
}
