package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// giteaGoSanitizers holds Gitea house-standard safe wrappers. These neutralize
// taint exactly where Gitea's own helpers already enforce safety, so Batou does
// not produce false positives on idiomatic Gitea code. Appended to
// (*GoCatalog).Sanitizers(). Derived from a real-repo coverage probe against
// Gitea main (~2,000+ call sites); IDs verified collision-free against the 153
// existing sanitizer IDs.
func giteaGoSanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- xorm/builder typed conditions (go-xorm/builder) ---
		// builder.Eq{}/In()/Like{}/... place the tainted value into a BOUND-ARGUMENT
		// position. ToSQL() emits "col = ?" with values returned as a separate args
		// slice passed to database/sql as parameters — the tainted value cannot alter
		// query structure. Safe alternative to builder.Expr(rawSQL)/Where(rawSQL).
		{
			ID:          "go.xorm.builder.typedcond",
			Language:    rules.LangGo,
			Pattern:     `\bbuilder\.(Eq|Neq|Gt|Gte|Lt|Lte|In|NotIn|Like|Between)\s*[\{(]`,
			ObjectType:  "builder",
			MethodName:  "builder.Eq/Neq/Gt/Gte/Lt/Lte/In/NotIn/Like/Between",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "go-xorm/builder typed condition constructors place tainted values in bound-argument (?) positions; ToSQL emits parameterized SQL with a separate args slice (neutralizes SQL injection)",
		},
		{
			ID:          "go.xorm.builder.cond",
			Language:    rules.LangGo,
			Pattern:     `builder\.Cond\b`,
			ObjectType:  "builder",
			MethodName:  "builder.Cond",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "go-xorm/builder.Cond — values inside a Cond are emitted as bound ? parameters by ToSQL (neutralizes SQL injection)",
		},

		// --- xorm parameterized .Where/.And/.Or with ? placeholder ---
		// A literal ? in the first arg means the tainted value is passed as a
		// trailing bound parameter, not concatenated. Scoped to the presence of ?
		// so a raw-string Where (no placeholder) is NOT suppressed — that variant
		// is still a real injection sink.
		{
			ID:          "go.xorm.where.parameterized",
			Language:    rules.LangGo,
			Pattern:     `\.(Where|And|Or)\([^)]*\?`,
			ObjectType:  "*xorm.Session",
			MethodName:  "Where/And/Or (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "xorm Session Where/And/Or with a ? placeholder binds the tainted value as a query parameter (neutralizes SQL injection); raw-string Where without ? is intentionally NOT matched",
		},

		// --- hostmatcher SSRF allowlist (modules/hostmatcher) ---
		// MatchHostName/MatchIPAddr return bool only when the destination passes
		// Gitea's configured allow/deny list. Bool-guard form mirrors the
		// already-registered go.filepath.islocal / go.url.isabs guards.
		{
			ID:          "go.hostmatcher.match",
			Language:    rules.LangGo,
			Pattern:     `\.MatchHostName\s*\(|\.MatchIPAddr\s*\(`,
			ObjectType:  "*hostmatcher.HostMatchList",
			MethodName:  "MatchHostName/MatchIPAddr",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Gitea hostmatcher.HostMatchList.MatchHostName/MatchIPAddr validate a destination host/IP against the configured allow/deny list before an outbound fetch (SSRF guard)",
		},

		// --- util path-join helpers (modules/util/path.go) — scoped to file sinks ---
		// PathJoinRel/PathJoinRelX path.Clean each element and produce a relative
		// path with ../ collapsed within scope; FilePathJoinAbs anchors to an
		// absolute base. Scoped to file read/write only (not command/redirect) —
		// neutralizes the lexical ../ traversal pattern the regex sink keys on.
		{
			ID:          "go.util.pathjoinrel",
			Language:    rules.LangGo,
			Pattern:     `util\.PathJoinRel\s*\(|util\.PathJoinRelX\s*\(`,
			ObjectType:  "",
			MethodName:  "util.PathJoinRel/PathJoinRelX",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Gitea util.PathJoinRel/PathJoinRelX path.Clean each element and produce a relative path with ../ segments collapsed within scope (CWE-22 traversal-token neutralization for file sinks)",
		},
		{
			ID:          "go.util.filepathjoinabs",
			Language:    rules.LangGo,
			Pattern:     `util\.FilePathJoinAbs\s*\(`,
			ObjectType:  "",
			MethodName:  "util.FilePathJoinAbs",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Gitea util.FilePathJoinAbs anchors to an absolute base and filepath.Clean-joins each sub element, collapsing ../ within scope (CWE-22 guard for file sinks)",
		},

		// --- httplib/util redirect & header encoders ---
		{
			ID:          "go.httplib.isrelativeurl",
			Language:    rules.LangGo,
			Pattern:     `httplib\.IsRelativeURL\s*\(`,
			ObjectType:  "",
			MethodName:  "httplib.IsRelativeURL",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect},
			Description: "Gitea httplib.IsRelativeURL — true only for relative URLs (no scheme/host), so a redirect target gated on it cannot leave the site (open-redirect guard)",
		},
		{
			ID:          "go.util.pathescapesegments",
			Language:    rules.LangGo,
			Pattern:     `util\.PathEscapeSegments\s*\(`,
			ObjectType:  "",
			MethodName:  "util.PathEscapeSegments",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkURLFetch},
			Description: "Gitea util.PathEscapeSegments percent-escapes each URL path segment (prevents path/segment injection in constructed URLs)",
		},
		{
			ID:          "go.httplib.contentdisposition",
			Language:    rules.LangGo,
			Pattern:     `httplib\.EncodeContentDisposition(Attachment|Inline)\s*\(`,
			ObjectType:  "",
			MethodName:  "httplib.EncodeContentDispositionAttachment/Inline",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Gitea httplib.EncodeContentDisposition* RFC 5987-encode a filename into a Content-Disposition header value (strips CR/LF, escapes — prevents HTTP header injection)",
		},

		// --- git ref-pattern validators (modules/git/ref.go) ---
		// IsValidRefPattern (bool guard) rejects invalid names; SanitizeRefPattern
		// replaces every invalid char with '_'. Pairs with the git
		// AddDynamicArguments command sink where a ref name flows into a git CLI arg.
		{
			ID:          "go.git.refpattern",
			Language:    rules.LangGo,
			Pattern:     `git\.IsValidRefPattern\s*\(|git\.SanitizeRefPattern\s*\(`,
			ObjectType:  "",
			MethodName:  "git.IsValidRefPattern/SanitizeRefPattern",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Gitea git.IsValidRefPattern/SanitizeRefPattern validate/strip a ref name to valid ref characters (no shell/arg metacharacters), pairing with the git AddDynamicArguments command sink",
		},
	}
}
