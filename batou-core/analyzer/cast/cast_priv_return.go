package cast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// Stage-2 structural check: unchecked return value of a privilege-drop call
// (BATOU-CAST-008, CWE-252 — Unchecked Return Value).
//
// The vulnerability class is narrow and well-defined: a setuid/setgid-family
// call that DROPS privileges (root -> unprivileged) can FAIL — for example with
// EAGAIN when RLIMIT_NPROC is hit, or EPERM in a restricted environment. If the
// program ignores the failure it keeps running with the original (root)
// privileges it intended to shed. This is the root cause of multiple real CVEs
// (e.g. the sendmail / Postfix setuid-failure class). The actionable, low-noise
// signal is exactly: the drop call's RETURN VALUE is discarded.
//
// Scope discipline (why this does not false-positive):
//   - Only the privilege-changing set* family is matched — not arbitrary libc
//     calls. memcpy/printf/etc. are never considered.
//   - The match requires the call to be the SOLE expression of a bare
//     expression_statement (`setuid(u);`). That structurally excludes every
//     pattern where the result IS consumed:
//       * `if (setuid(u) != 0) ...`   -> call lives under the if condition
//       * `r = setuid(u);`            -> call lives under assignment_expression
//       * `return setuid(u);`         -> call lives under return_statement
//       * `while (setresuid(...))`    -> call lives under the loop condition
//     so this fires only when the return is genuinely thrown away.
//
// These are unique reserved POSIX symbols, so there is no bare-name collision
// with application code (no app method is named setresuid).

// privDropFuncs is the set of POSIX privilege-changing syscalls whose failure
// must be checked. A discarded return value here is CWE-252.
var privDropFuncs = map[string]string{
	"setuid":    "real user ID",
	"setgid":    "real group ID",
	"seteuid":   "effective user ID",
	"setegid":   "effective group ID",
	"setreuid":  "real and effective user IDs",
	"setregid":  "real and effective group IDs",
	"setresuid": "real, effective, and saved user IDs",
	"setresgid": "real, effective, and saved group IDs",
}

// checkUncheckedPrivDrop emits BATOU-CAST-008 when a privilege-drop call's
// return value is discarded (the call is the entire expression of a bare
// expression_statement). n is a call_expression node.
func (c *cChecker) checkUncheckedPrivDrop(n *ast.Node) {
	funcName := cCallName(n)
	which, ok := privDropFuncs[funcName]
	if !ok {
		return
	}

	// The call must be the SOLE child expression of a bare expression_statement
	// for the return to count as discarded. tree-sitter-c wraps a standalone
	// `setuid(u);` as expression_statement -> call_expression. Any consuming
	// context (assignment, if/while condition, return, cast, larger expression)
	// puts a different node between the call and its statement, so this check is
	// false precisely when the result is used.
	parent := n.Parent()
	if parent == nil || parent.Type() != "expression_statement" {
		return
	}
	// Defend against `setuid(u), other();` (comma expression smuggled into one
	// statement) by requiring the call to be the statement's only named child.
	if named := parent.NamedChildren(); len(named) != 1 || named[0] != n {
		return
	}

	line := int(n.StartRow()) + 1
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-008",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unchecked return value of privilege-drop call " + funcName + "()",
		Description: funcName + "() changes the " + which + " but its return value is discarded. " +
			"Privilege-drop syscalls can fail (e.g. EAGAIN under RLIMIT_NPROC, EPERM in a restricted " +
			"environment); if the failure is ignored the process keeps its original elevated privileges, " +
			"defeating the privilege separation (CWE-252).",
		FilePath:    c.filePath,
		LineNumber:  line,
		MatchedText: truncate(n.Text(), 200),
		Suggestion: "Check the return value and abort on failure: if (" + funcName + "(...) != 0) { perror(\"" +
			funcName + "\"); _exit(1); }. Never continue execution when a privilege drop fails.",
		CWEID:         "CWE-252",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"unchecked-return", "privilege-drop", "privilege-management", "ast"},
	})
}

// ---------------------------------------------------------------------------
// Supplementary-group drop ordering (BATOU-CAST-017, CWE-252 / CWE-271).
//
// When a privileged process drops to an unprivileged user it must drop its
// SUPPLEMENTARY groups (setgroups/initgroups) BEFORE the final setuid(). A
// function that calls setgid() AND setuid() — signalling a deliberate
// privilege drop — but never setgroups()/initgroups() leaves root's
// supplementary groups attached to the now-"unprivileged" process, so it can
// still access group-restricted resources. This is the canonical
// privilege-separation ordering bug (e.g. the historical ping / wu-ftpd class).
//
// Precision / why this does not false-positive:
//   - Only the PERMANENT-drop forms setuid()/setgid() are matched. When a
//     privileged process calls these they change ALL of the real, effective,
//     and saved IDs — the irreversible "shed root" shape. The EFFECTIVE-only
//     setters seteuid()/setegid() are deliberately EXCLUDED: those are used for
//     a TEMPORARY privilege swap that is later restored (e.g. dropbear's
//     svr-agentfwd seteuid()/restore), where dropping supplementary groups
//     would be wrong. The partial setresuid(-1,...) form is likewise excluded.
//   - Both setgid AND setuid must appear in the same function. A program that
//     only changes the uid (no setgid) is not signalling a full identity drop
//     and is not flagged.
//   - If setgroups OR initgroups appears anywhere in the function, the function
//     is doing the right thing and nothing fires.
//   - These are unique reserved POSIX symbols, so there is no bare-name
//     collision with application code.
//
// Implemented independently from the POSIX privilege API and the CWE-252/CWE-271
// definitions.
// ---------------------------------------------------------------------------

// checkPrivDropGroupOrder emits BATOU-CAST-017 for a function that permanently
// drops both uid and gid but never drops supplementary groups. n is a
// function_definition.
func (c *cChecker) checkPrivDropGroupOrder(n *ast.Node) {
	body := n.ChildByFieldName("body")
	if body == nil {
		return
	}
	var sawSetgid, sawSetuid, sawGroupDrop bool
	var setuidCall *ast.Node
	body.Walk(func(w *ast.Node) bool {
		if w.Type() != "call_expression" {
			return true
		}
		switch cCallName(w) {
		// Only the permanent all-ID drop forms — NOT seteuid/setegid (temporary
		// swaps) or setresuid/setresgid (often partial -1 changes).
		case "setgid":
			sawSetgid = true
		case "setuid":
			sawSetuid = true
			if setuidCall == nil {
				setuidCall = w
			}
		case "setgroups", "initgroups":
			sawGroupDrop = true
		}
		return true
	})
	if !sawSetgid || !sawSetuid || sawGroupDrop {
		return
	}
	anchor := setuidCall
	if anchor == nil {
		anchor = n
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-017",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Privilege drop omits setgroups()/initgroups()",
		Description: "This function drops the user ID (setuid family) and group ID (setgid family) but never " +
			"calls setgroups() or initgroups(). Without dropping the supplementary groups, the process keeps " +
			"root's group memberships after the uid/gid change and can still reach group-restricted resources, " +
			"defeating the privilege separation (CWE-252 / CWE-271).",
		FilePath:      c.filePath,
		LineNumber:    int(anchor.StartRow()) + 1,
		MatchedText:   truncate(anchor.Text(), 200),
		Suggestion:    "Drop supplementary groups before the final setuid(): call setgroups(0, NULL) (or initgroups(user, gid)), then setgid(gid), then setuid(uid), checking each return value.",
		CWEID:         "CWE-252",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"privilege-drop", "supplementary-groups", "privilege-management", "ast"},
	})
}
