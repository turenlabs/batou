package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// goGiteaSinks returns Gitea-codebase-specific Go sinks, appended to the tail
// of (*GoCatalog).Sinks(). Kept in its own file so the large shared go_sinks.go
// literal stays untouched. IDs verified collision-free against go_sinks.go.
func goGiteaSinks() []taint.SinkDef {
	return []taint.SinkDef{
		// --- (1) git.NewCommand argument injection (CWE-88) ---
		// (*gitcmd.Command).AddDynamicArguments(args ...string) appends
		// caller-supplied strings to a git argv. Unlike the typed
		// AddArguments(...internal.CmdArg) — which only accepts the compile-time
		// CmdArg allowlist and is intentionally NOT a sink — AddDynamicArguments
		// takes raw strings, so a tainted ref/branch/path reaching it is git
		// argument injection. Variadic → arg -1 (all positions dangerous).
		// Pairs with the go.git.refpattern sanitizer (IsValidRefPattern /
		// SanitizeRefPattern) so validated refs do not false-positive.
		{
			ID:            "go.gitea.gitcmd.adddynamicarguments",
			Category:      taint.SnkCommand,
			Language:      rules.LangGo,
			Pattern:       `\.AddDynamicArguments\s*\(`,
			ObjectType:    "*gitcmd.Command",
			MethodName:    "AddDynamicArguments",
			DangerousArgs: []int{-1},
			Severity:      rules.High,
			Description:   "(*git/gitcmd.Command).AddDynamicArguments appends caller-supplied strings to a git argv — tainted refs/branches/paths cause git argument injection (CWE-88). Validate with git.IsValidRefPattern / SanitizeRefPattern before passing, or use the typed AddArguments(...CmdArg) for fixed flags.",
			CWEID:         "CWE-88",
			OWASPCategory: "A03:2021-Injection",
		},

		// --- (2) xorm sinks on Gitea's local db.Engine / db.Session ---
		// Gitea funnels queries through models/db.GetEngine(ctx) (returns the
		// LOCAL interface db.Engine, not xorm.Engine) and db.Session. The
		// existing group:xorm.* entries don't cover Where/Exec/Join/Cols/Select
		// and don't bind the db.Engine/db.Session receiver type. These fire only
		// when a TAINTED value reaches the SQL/identifier argument — literal
		// parameterized queries (Exec("... ?", id)) have a constant arg-0 and
		// never taint. The go.xorm.* sanitizers neutralize builder.Eq{} and
		// `?`-placeholder Where/And/Or.
		{ID: "go.gitea.db.engine.where", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Where\s*\(`, ObjectType: "db.Engine", MethodName: "Where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "(db.Engine).Where(cond) via Gitea db.GetEngine(ctx) — a string-concatenated condition is SQL injection (CWE-89); use builder.Eq{}/builder.In{} or a `col = ?` placeholder with bound args.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.engine.exec", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Exec\s*\(`, ObjectType: "db.Engine", MethodName: "Exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "(db.Engine).Exec(sqlOrArgs) via Gitea db.GetEngine(ctx) — tainted SQL text is injection (CWE-89); pass parameterized `?` placeholders with bound args.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.engine.join", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Join\s*\(`, ObjectType: "db.Engine", MethodName: "Join", DangerousArgs: []int{1, 2}, Severity: rules.Critical, Description: "(db.Engine).Join(op, table, cond) — a tainted table name or join condition is SQL injection (CWE-89). Use a fixed table identifier and a placeholder condition.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.engine.cols", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Cols\s*\(`, ObjectType: "db.Engine", MethodName: "Cols", DangerousArgs: []int{-1}, Severity: rules.High, Description: "(db.Engine).Cols(colNames...) — column identifiers cannot be parameterized; a tainted column name is SQL injection (CWE-89). Validate against a static allowlist.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.engine.select", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Select\s*\(`, ObjectType: "db.Engine", MethodName: "Select", DangerousArgs: []int{0}, Severity: rules.High, Description: "(db.Engine).Select(colsExpr) — a tainted projection expression is SQL injection (CWE-89). Use fixed column lists, not interpolated identifiers.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},

		{ID: "go.gitea.db.session.where", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Where\s*\(`, ObjectType: "db.Session", MethodName: "Where", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "(db.Session).Where(cond) — a raw string condition is SQL injection (CWE-89); use builder.Eq{} or a `col = ?` placeholder with bound args.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.session.exec", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Exec\s*\(`, ObjectType: "db.Session", MethodName: "Exec", DangerousArgs: []int{0}, Severity: rules.Critical, Description: "(db.Session).Exec(sqlOrArgs) — tainted SQL text is injection (CWE-89). Use parameterized `?` placeholders.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.session.join", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Join\s*\(`, ObjectType: "db.Session", MethodName: "Join", DangerousArgs: []int{1, 2}, Severity: rules.Critical, Description: "(db.Session).Join(op, table, cond) — a tainted table name or join condition is SQL injection (CWE-89). Use a fixed table identifier and a placeholder condition.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.session.cols", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Cols\s*\(`, ObjectType: "db.Session", MethodName: "Cols", DangerousArgs: []int{-1}, Severity: rules.High, Description: "(db.Session).Cols(colNames...) — a tainted column name is SQL injection (CWE-89). Validate against a static allowlist.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
		{ID: "go.gitea.db.session.select", Category: taint.SnkSQLQuery, Language: rules.LangGo, Pattern: `\.Select\s*\(`, ObjectType: "db.Session", MethodName: "Select", DangerousArgs: []int{0}, Severity: rules.High, Description: "(db.Session).Select(colsExpr) — a tainted projection is SQL injection (CWE-89). Use fixed column lists.", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection"},
	}
}
