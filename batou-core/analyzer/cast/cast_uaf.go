package cast

import (
	"strconv"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// Stage-1 intraprocedural use-after-free (BATOU-CAST-007, CWE-416) and
// double-free (BATOU-CAST-006, CWE-415) detection.
//
// This replaces the regex layer's brace-reset heuristic (MEM-004/007/008) with
// real AST scoping. A per-function recursive block scan tracks freed pointers
// in source order. The single most important FP-suppression rule is the BRANCH
// RULE: a free inside a conditional/loop block is path-conditional and must NOT
// taint the straight-line code after the branch (otherwise the classic
// `if (err) { free(p); return; } use(p);` cleanup pattern false-positives).
// We implement that for free by SCOPE: frees in an enclosing block taint uses
// in nested blocks (a real UAF — the free definitely happened first on that
// path), but frees that occur inside a block never leak back to the enclosing
// block's later statements.
//
// Only plain-identifier pointers are tracked (free(p), not free(s->buf)) and a
// reassignment / NULL-set / realloc clears the tracked state — both conservative
// choices that under-fire rather than over-fire. Verified by cast_test.go
// fixtures (TP + must-not-fire FP) and a real-repo A/B; the c/cpp bench is
// CWE-disjoint (CWE-120 only) so these CWE-415/416 checks are bench-neutral.

type freedPtr struct {
	line      int
	sameBlock bool // freed in the current block (straight-line) vs inherited (conditional)
}

// derefingCalls are libc functions that DEREFERENCE their pointer argument
// (read/write the pointed-to memory). Passing a freed pointer to one of these is
// a genuine use-after-free. We use an allowlist rather than a denylist so that
// passing a freed pointer's *value* to a comparison / logger / free-wrapper
// (expect_ptr_eq(p), printf("%p", p), freeReplyObject(p)) does NOT false-positive
// — only a real dereference does.
var derefingCalls = map[string]bool{
	"strcpy": true, "strncpy": true, "strcat": true, "strncat": true,
	"strlcpy": true, "strlcat": true, "strlen": true, "strnlen": true,
	"strdup": true, "strndup": true, "strcmp": true, "strncmp": true,
	"strcasecmp": true, "strncasecmp": true, "strchr": true, "strrchr": true,
	"strstr": true, "strtok": true, "strspn": true, "strcspn": true,
	"memcpy": true, "memmove": true, "memcmp": true, "memchr": true, "memset": true,
	"sprintf": true, "snprintf": true, "sscanf": true, "fputs": true, "puts": true,
}

func (c *cChecker) checkFunctionFlow(fnDef *ast.Node) {
	body := fnDef.ChildByFieldName("body")
	if body == nil || body.Type() != "compound_statement" {
		return
	}
	c.scanFlowBlock(body, map[string]freedPtr{})
}

// scanFlowBlock processes the direct child statements of a compound_statement in
// source order. `enclosing` carries pointers freed in ENCLOSING blocks.
func (c *cChecker) scanFlowBlock(block *ast.Node, enclosing map[string]freedPtr) {
	freed := map[string]freedPtr{}
	for k, v := range enclosing {
		freed[k] = freedPtr{line: v.line, sameBlock: false} // inherited => conditional
	}
	for i := 0; i < block.ChildCount(); i++ {
		stmt := block.Child(i)
		if stmt == nil || !stmt.IsNamed() {
			continue
		}
		switch stmt.Type() {
		case "if_statement", "for_statement", "while_statement", "do_statement", "switch_statement":
			if cond := stmt.ChildByFieldName("condition"); cond != nil {
				c.flagUses(cond, freed)
			}
			for _, b := range nestedBodies(stmt) {
				if b.Type() == "compound_statement" {
					c.scanFlowBlock(b, freed)
				} else {
					c.scanFlowSingle(b, freed)
				}
			}
		case "return_statement", "break_statement", "continue_statement", "goto_statement":
			c.flagUses(stmt, freed)
			return // straight-line path ends; remaining siblings are dead/other-path
		case "compound_statement":
			c.scanFlowBlock(stmt, freed)
		default:
			c.scanFlowSingle(stmt, freed)
		}
	}
}

// scanFlowSingle handles one straight-line statement: a free (track/double-free),
// an assignment (clears the LHS), or uses of freed pointers.
func (c *cChecker) scanFlowSingle(stmt *ast.Node, freed map[string]freedPtr) {
	if name := freedTarget(stmt, c.language); name != "" {
		if info, ok := freed[name]; ok {
			conf := "high"
			if !info.sameBlock {
				conf = "medium"
			}
			c.emitMemFlow("BATOU-CAST-006", rules.Critical, "CWE-415",
				"Double free of '"+name+"'",
				"'"+name+"' is freed again here after being freed on line "+strconv.Itoa(info.line)+
					" with no intervening reassignment. Freeing the same allocation twice corrupts allocator metadata (double-free) and is exploitable for arbitrary writes.",
				"Set the pointer to NULL immediately after freeing it, or restructure so each allocation is freed exactly once.",
				stmt, conf,
				[]string{"double-free", "memory-safety", "use-after-free", "ast"})
		} else {
			freed[name] = freedPtr{line: int(stmt.StartRow()) + 1, sameBlock: true}
		}
		return
	}
	if lhs := assignTarget(stmt); lhs != "" {
		delete(freed, lhs) // realloc / reassign / = NULL clears the freed state
	}
	c.flagUses(stmt, freed)
}

// flagUses scans `node` for dereference / subscript / field / call-arg uses of a
// freed pointer and emits a use-after-free for each, dropping the pointer from
// the freed-set (one finding per pointer per free).
func (c *cChecker) flagUses(node *ast.Node, freed map[string]freedPtr) {
	if node == nil || len(freed) == 0 {
		return
	}
	node.Walk(func(n *ast.Node) bool {
		var used string
		switch n.Type() {
		case "field_expression": // p->x / p.x
			used = identName(n.ChildByFieldName("argument"))
		case "pointer_expression": // *p (dereference) — but NOT &p (address-of)
			if op := n.ChildByFieldName("operator"); op != nil && op.Text() == "*" {
				used = identNameFromChildren(n)
			}
		case "subscript_expression": // p[i]
			used = identName(n.ChildByFieldName("argument"))
		case "call_expression":
			// Only a call that DEREFERENCES its pointer arg is a UAF use; passing
			// the freed pointer's value to a comparison/logger/free-wrapper is not.
			if derefingCalls[cCallName(n)] {
				if al := findChild(n, "argument_list"); al != nil {
					for _, a := range al.NamedChildren() {
						if name := identName(a); name != "" {
							c.emitUAF(name, n, freed)
						}
					}
				}
			}
			return true // keep descending (nested expressions)
		}
		if used != "" {
			c.emitUAF(used, n, freed)
		}
		return true
	})
}

func (c *cChecker) emitUAF(name string, n *ast.Node, freed map[string]freedPtr) {
	info, ok := freed[name]
	if !ok {
		return
	}
	conf := "high"
	if !info.sameBlock {
		conf = "medium"
	}
	c.emitMemFlow("BATOU-CAST-007", rules.Critical, "CWE-416",
		"Use after free of '"+name+"'",
		"'"+name+"' is used here after being freed on line "+strconv.Itoa(info.line)+
			". Dereferencing or passing a freed pointer reads/writes reclaimed memory (use-after-free), a critical, often-exploitable memory-safety bug.",
		"Do not use the pointer after free. Set it to NULL after freeing and re-allocate before the next use, or restructure the lifetime so the value is read before it is freed.",
		n, conf,
		[]string{"use-after-free", "memory-safety", "dangling-pointer", "ast"})
	delete(freed, name) // one finding per pointer per free
}

func (c *cChecker) emitMemFlow(ruleID string, sev rules.Severity, cwe, title, desc, suggestion string, n *ast.Node, conf string, tags []string) {
	c.findings = append(c.findings, rules.Finding{
		RuleID:        ruleID,
		Severity:      sev,
		SeverityLabel: sev.String(),
		Title:         title,
		Description:   desc,
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    suggestion,
		CWEID:         cwe,
		OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Language:      c.language,
		Confidence:    conf,
		Tags:          tags,
	})
}

// nestedBodies returns the body block(s) of a control-flow statement.
func nestedBodies(stmt *ast.Node) []*ast.Node {
	var out []*ast.Node
	switch stmt.Type() {
	case "if_statement":
		if b := stmt.ChildByFieldName("consequence"); b != nil {
			out = append(out, b)
		}
		if b := stmt.ChildByFieldName("alternative"); b != nil {
			// `else` field wraps the alternative; unwrap one level if needed.
			if b.Type() == "else_clause" {
				if nb := firstNamedChild(b); nb != nil {
					out = append(out, nb)
				}
			} else {
				out = append(out, b)
			}
		}
	default: // for / while / do / switch
		if b := stmt.ChildByFieldName("body"); b != nil {
			out = append(out, b)
		}
	}
	return out
}

// freedTarget returns the plain-identifier name freed by `stmt` (free(p) in C,
// also delete/delete[] in C++), or "" if the statement is not a free of a
// simple identifier.
func freedTarget(stmt *ast.Node, lang rules.Language) string {
	var name string
	stmt.Walk(func(n *ast.Node) bool {
		if name != "" {
			return false
		}
		switch n.Type() {
		case "call_expression":
			if cCallName(n) == "free" {
				if al := findChild(n, "argument_list"); al != nil {
					nc := al.NamedChildren()
					if len(nc) == 1 {
						name = identName(nc[0])
					}
				}
			}
		case "delete_expression": // C++ delete p / delete[] p
			name = identNameFromChildren(n)
		}
		return true
	})
	return name
}

// assignTarget returns the identifier being (re)bound by `stmt` — an
// assignment `p = ...`, a declaration `T *p = ...`, or a C++ `p.reset()` —
// which clears p's freed state. Returns "" otherwise.
func assignTarget(stmt *ast.Node) string {
	var target string
	stmt.Walk(func(n *ast.Node) bool {
		if target != "" {
			return false
		}
		switch n.Type() {
		case "assignment_expression":
			target = identName(n.ChildByFieldName("left"))
		case "init_declarator":
			target = declaratorIdentifier(n.ChildByFieldName("declarator"))
		case "call_expression":
			// C++ smart-pointer reset: p.reset() / p.reset(q)
			fn := n.NamedChildren()
			if len(fn) > 0 && fn[0].Type() == "field_expression" {
				if fn[0].ChildByFieldName("field") != nil && fn[0].ChildByFieldName("field").Text() == "reset" {
					target = identName(fn[0].ChildByFieldName("argument"))
				}
			}
		}
		return true
	})
	return target
}

// identName returns n's text if n is (or unwraps to) a plain identifier, else "".
func identName(n *ast.Node) string {
	if n == nil {
		return ""
	}
	if n.Type() == "identifier" {
		return n.Text()
	}
	return ""
}

// identNameFromChildren returns the plain-identifier operand of a unary
// expression (pointer_expression `*p`, delete_expression `delete p`).
func identNameFromChildren(n *ast.Node) string {
	for _, ch := range n.NamedChildren() {
		if ch.Type() == "identifier" {
			return ch.Text()
		}
	}
	return ""
}
