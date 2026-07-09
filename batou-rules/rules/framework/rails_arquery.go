package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-013: ActiveRecord query methods that interpolate raw SQL
//
// Several ActiveRecord::Relation/Calculations APIs accept a raw SQL fragment in
// their first positional argument (a column name, ORDER BY clause, or SET
// clause). When that fragment is built from user input via string interpolation
// (`#{...}`) or a direct `params[...]` argument, the input reaches the SQL
// string unescaped — SQL injection (CWE-89). These complement the existing
// .where()/.order() coverage in BATOU-FW-RAILS-006.
//
// We only fire on the *dangerous shape* (interpolation or raw params/request
// argument), never on the bare method name — `Model.pluck(:id)` and
// `posts.sum(:views)` with a symbol/hardcoded column are safe and stay clean.
// ---------------------------------------------------------------------------

var (
	// Calculation/aggregate methods whose column argument is raw SQL:
	//   calculate(:sum, "...#{x}"), sum("..."), average / minimum / maximum,
	//   pluck("..."), reorder("...").  String interpolation form.
	reRailsCalcInterp = regexp.MustCompile(`\.(?:calculate|pluck|reorder|sum|average|minimum|maximum)\s*\(\s*(?:[:a-zA-Z_]\w*\s*,\s*)?"[^"]*#\{`)
	// Same methods with a raw params/request argument:
	//   pluck(params[:col]), reorder(params[:sort]), calculate(:sum, params[:c])
	reRailsCalcParams = regexp.MustCompile(`\.(?:calculate|pluck|reorder|sum|average|minimum|maximum)\s*\(\s*(?:[:a-zA-Z_]\w*\s*,\s*)?(?:params|request|cookies)\s*\[`)

	// update_all SET clause is raw SQL: update_all("col = '#{x}'") or
	// update_all(params[:set]). The hash form update_all(col: val) is safe and
	// is not matched here.
	reRailsUpdateAllInterp = regexp.MustCompile(`\.update_all\s*\(\s*"[^"]*#\{`)
	reRailsUpdateAllParams = regexp.MustCompile(`\.update_all\s*\(\s*(?:params|request|cookies)\s*\[`)

	// find_or_create_by("...#{x}...") — string-condition form that interpolates
	// user input into a SQL fragment. These method names are ActiveRecord-
	// exclusive so a bare match is safe.
	reRailsExistsInterp = regexp.MustCompile(`\.(?:find_or_create_by|find_or_initialize_by)\s*\(\s*"[^"]*#\{`)

	// exists?("raw sql #{x}") is also an ActiveRecord SQLi sink, but `exists?`
	// collides with non-AR receivers (I18n.exists?, a Set#exists?, key lookups).
	// Match it only when the receiver is NOT one of those known stdlib/i18n
	// modules — `reRailsExistsRecv` captures the receiver token immediately
	// before `.exists?(`.
	reRailsExistsInterpRecv = regexp.MustCompile(`(\w+(?:::\w+)*)\.exists\?\s*\(\s*"[^"]*#\{`)
)

// railsExistsReceiverIsNonAR reports whether the receiver of a `.exists?(` call
// is a well-known non-ActiveRecord type whose #exists? takes a key/path, not a
// SQL condition (I18n key lookup, filesystem existence checks, etc.).
func railsExistsReceiverIsNonAR(recv string) bool {
	switch recv {
	case "I18n", "File", "FileTest", "Dir", "Pathname", "Set":
		return true
	}
	return false
}

// reRailsInterpExpr captures the expression inside each `#{...}` on a line.
var reRailsInterpExpr = regexp.MustCompile(`#\{([^}]*)\}`)

// railsInterpHasTaint reports whether ANY interpolation segment on the line
// embeds a potentially user-controlled value rather than a pure framework
// constant. A column name built only from constants — `#{Group.table_name}`,
// `#{User.primary_key}`, `#{Post::COLUMN}` — is NOT a SQL injection: those are
// developer-fixed identifiers, not request data. ActiveRecord-heavy codebases
// (GitLab, Discourse) interpolate table/column metadata into pluck/order
// strings constantly; flagging those would be pure noise.
//
// A segment is treated as tainted when it contains an explicit request source
// token, or its leading identifier is a lowercase local/variable (`#{col}`,
// `#{sort_dir}`) rather than an UpperCamelCase Constant reference. This keeps
// `pluck("#{params[:col]}")` and `order("#{sort}")` flagged while clearing
// constant-only interpolations.
func railsInterpHasTaint(line string) bool {
	matches := reRailsInterpExpr.FindAllStringSubmatch(line, -1)
	if matches == nil {
		return false
	}
	for _, m := range matches {
		expr := strings.TrimSpace(m[1])
		if expr == "" {
			continue
		}
		// Explicit request/IO source anywhere in the segment.
		if strings.Contains(expr, "params") || strings.Contains(expr, "request") ||
			strings.Contains(expr, "cookies") || strings.Contains(expr, "session") ||
			strings.Contains(expr, "gets") || strings.Contains(expr, "env[") ||
			strings.Contains(expr, "ENV[") {
			return true
		}
		// Leading token: a lowercase-led identifier is a local variable / method
		// arg and is treated as potentially tainted. An UpperCamelCase token is a
		// Ruby Constant (model/class/module) reference — fixed, not user input.
		r0 := expr[0]
		if r0 == '_' || (r0 >= 'a' && r0 <= 'z') || r0 == '@' {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-013: ActiveRecord aggregate/projection SQL injection
// ---------------------------------------------------------------------------

type RailsCalcSQLi struct{}

func (r *RailsCalcSQLi) ID() string                      { return "BATOU-FW-RAILS-013" }
func (r *RailsCalcSQLi) Name() string                    { return "RailsCalcSQLi" }
func (r *RailsCalcSQLi) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RailsCalcSQLi) Description() string {
	return "Detects ActiveRecord calculate/sum/average/minimum/maximum/pluck/reorder/update_all with an interpolated or raw-params column/SET argument, which reaches the SQL string unescaped (SQL injection)."
}
func (r *RailsCalcSQLi) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsCalcSQLi) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()

	type check struct {
		re    *regexp.Regexp
		title string
		desc  string
		// interp marks string-interpolation checks: these only fire when the
		// interpolated value is potentially user-controlled (railsInterpHasTaint),
		// so a constant-only column like pluck("#{Group.table_name}") stays clean.
		interp bool
	}
	checks := []check{
		{
			re:     reRailsCalcInterp,
			interp: true,
			title:  "Rails calculate/pluck/reorder with SQL string interpolation (SQLi)",
			desc:   "An ActiveRecord aggregate/projection method (calculate, sum, average, minimum, maximum, pluck, reorder) is called with a string containing interpolation of a user-controlled value. The column/order argument is appended to the SQL verbatim, so the interpolation is a SQL injection.",
		},
		{
			re:    reRailsCalcParams,
			title: "Rails calculate/pluck/reorder with raw params column (SQLi)",
			desc:  "An ActiveRecord aggregate/projection method receives a raw params/request value as its column/order argument. ActiveRecord does not escape column names, so attacker-controlled input becomes part of the SQL.",
		},
		{
			re:     reRailsUpdateAllInterp,
			interp: true,
			title:  "Rails update_all with SQL string interpolation (SQLi)",
			desc:   "update_all's string form builds the SET clause as raw SQL. Interpolating a user-controlled value into that string is a SQL injection; use the hash form update_all(col: value) instead.",
		},
		{
			re:    reRailsUpdateAllParams,
			title: "Rails update_all with raw params SET clause (SQLi)",
			desc:  "update_all receives a raw params/request value as its SET clause. The string form is raw SQL; pass a hash of column=>value instead.",
		},
		{
			re:     reRailsExistsInterp,
			interp: true,
			title:  "Rails find_or_create_by with SQL string interpolation (SQLi)",
			desc:   "find_or_create_by/find_or_initialize_by is called with an interpolated string condition embedding a user-controlled value. The string form is treated as raw SQL; the interpolation enables SQL injection. Use a hash condition or bind parameters.",
		},
	}

	emit := func(i int, line, title, desc string) {
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         title,
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Use a symbol/whitelisted column name (Model.pluck(:id)), the hash form (update_all(views: 0)), or bind parameters (.where('col = ?', value)). Never interpolate user input into a column, ORDER BY, or SET fragment.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "sql-injection", "activerecord"},
		})
	}

	for i, line := range lines {
		if isComment(line) {
			continue
		}
		matched := false
		for _, c := range checks {
			if !rules.GMatchLower(c.re, line, lowered[i]) {
				continue
			}
			// Interpolation checks require the interpolated value to be
			// user-controlled — a constant-only column/SET fragment is safe.
			if c.interp && !railsInterpHasTaint(line) {
				continue
			}
			emit(i, line, c.title, c.desc)
			matched = true
			break // one finding per line
		}
		if matched {
			continue
		}
		// exists?("...#{x}...") — guard against non-AR receivers (I18n.exists?,
		// File.exists?, etc.) whose argument is a key/path, not a SQL condition.
		if m := rules.GFindSubmatchLower(reRailsExistsInterpRecv, line, lowered[i]); m != nil {
			// Constant-only interpolation (e.g. #{User.table_name}) is not tainted.
			if !railsInterpHasTaint(line) {
				continue
			}
			recv := m[1]
			// The captured receiver may be qualified (A::B); take the last segment
			// for the well-known-module check, and also reject the full token.
			parts := strings.Split(recv, "::")
			last := parts[len(parts)-1]
			if railsExistsReceiverIsNonAR(recv) || railsExistsReceiverIsNonAR(last) {
				continue
			}
			emit(i, line,
				"Rails exists? with SQL string interpolation (SQLi)",
				"ActiveRecord exists? is called with an interpolated string condition. The string form is treated as raw SQL; interpolating user input enables SQL injection. Use a hash condition or bind parameters.")
		}
	}
	return findings
}
