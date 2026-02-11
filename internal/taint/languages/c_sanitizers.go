package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

func (c *CCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Bounded string operations ---
		{
			ID:          "c.bounds.strlcpy",
			Language:    rules.LangC,
			Pattern:     `\bstrlcpy\s*\(`,
			ObjectType:  "",
			MethodName:  "strlcpy",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Bounded string copy (prevents buffer overflow)",
		},
		{
			ID:          "c.bounds.strlcat",
			Language:    rules.LangC,
			Pattern:     `\bstrlcat\s*\(`,
			ObjectType:  "",
			MethodName:  "strlcat",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Bounded string concatenation (prevents buffer overflow)",
		},
		{
			ID:          "c.bounds.snprintf",
			Language:    rules.LangC,
			Pattern:     `\bsnprintf\s*\(`,
			ObjectType:  "",
			MethodName:  "snprintf",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Bounded formatted string write (prevents buffer overflow)",
		},
		{
			ID:          "c.bounds.strncpy_sized",
			Language:    rules.LangC,
			Pattern:     `\bstrncpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(`,
			ObjectType:  "",
			MethodName:  "strncpy (with sizeof)",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Bounded string copy with sizeof-derived size (prevents buffer overflow)",
		},
		{
			ID:          "c.bounds.strncat",
			Language:    rules.LangC,
			Pattern:     `\bstrncat\s*\(`,
			ObjectType:  "",
			MethodName:  "strncat",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Bounded string concatenation with length limit",
		},

		// --- Input validation / numeric conversion ---
		{
			ID:          "c.validate.strtol",
			Language:    rules.LangC,
			Pattern:     `\bstrtol\s*\(`,
			ObjectType:  "",
			MethodName:  "strtol",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to long conversion with error checking (restricts to numeric)",
		},
		{
			ID:          "c.validate.strtoul",
			Language:    rules.LangC,
			Pattern:     `\bstrtoul\s*\(`,
			ObjectType:  "",
			MethodName:  "strtoul",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "String to unsigned long conversion with error checking",
		},
		{
			ID:          "c.validate.strtod",
			Language:    rules.LangC,
			Pattern:     `\bstrtod\s*\(`,
			ObjectType:  "",
			MethodName:  "strtod",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String to double conversion with error checking",
		},
		{
			ID:          "c.validate.atoi",
			Language:    rules.LangC,
			Pattern:     `\batoi\s*\(`,
			ObjectType:  "",
			MethodName:  "atoi",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "String to integer conversion (restricts to numeric values)",
		},

		// --- Memory clearing ---
		{
			ID:          "c.mem.memset",
			Language:    rules.LangC,
			Pattern:     `\bmemset\s*\(`,
			ObjectType:  "",
			MethodName:  "memset",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Memory clearing for sensitive data erasure",
		},
		{
			ID:          "c.mem.explicit_bzero",
			Language:    rules.LangC,
			Pattern:     `\bexplicit_bzero\s*\(`,
			ObjectType:  "",
			MethodName:  "explicit_bzero",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Guaranteed memory clearing that cannot be optimized away",
		},
		{
			ID:          "c.mem.memset_s",
			Language:    rules.LangC,
			Pattern:     `\bmemset_s\s*\(`,
			ObjectType:  "",
			MethodName:  "memset_s",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "C11 secure memory clearing that cannot be optimized away",
		},

		// --- SQL parameterization ---
		{
			ID:          "c.sql.sqlite3_prepare",
			Language:    rules.LangC,
			Pattern:     `\bsqlite3_prepare\w*\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite prepared statement (parameterized query)",
		},
		{
			ID:          "c.sql.sqlite3_bind",
			Language:    rules.LangC,
			Pattern:     `\bsqlite3_bind_\w+\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_bind_*",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite parameter binding (prevents SQL injection)",
		},
		{
			ID:          "c.sql.mysql_real_escape_string",
			Language:    rules.LangC,
			Pattern:     `\bmysql_real_escape_string\s*\(`,
			ObjectType:  "",
			MethodName:  "mysql_real_escape_string",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL string escaping (prevents SQL injection)",
		},
		{
			ID:          "c.sql.mysql_stmt_prepare",
			Language:    rules.LangC,
			Pattern:     `\bmysql_stmt_prepare\s*\(`,
			ObjectType:  "",
			MethodName:  "mysql_stmt_prepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQL prepared statement (parameterized query)",
		},
		{
			ID:          "c.sql.pqexecparams",
			Language:    rules.LangC,
			Pattern:     `\bPQexecParams\s*\(`,
			ObjectType:  "",
			MethodName:  "PQexecParams",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL parameterized query (prevents SQL injection)",
		},
		{
			ID:          "c.sql.pqprepare",
			Language:    rules.LangC,
			Pattern:     `\bPQprepare\s*\(`,
			ObjectType:  "",
			MethodName:  "PQprepare",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "PostgreSQL prepared statement (prevents SQL injection)",
		},
		{
			ID:          "c.sql.sqlite3_mprintf",
			Language:    rules.LangC,
			Pattern:     `\bsqlite3_mprintf\s*\(\s*"%q"`,
			ObjectType:  "",
			MethodName:  "sqlite3_mprintf(%q)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite string escaping via %q format (prevents SQL injection)",
		},

		// --- Bounds-checked memory operations (C11 Annex K) ---
		{
			ID:          "c.bounds.memcpy_s",
			Language:    rules.LangC,
			Pattern:     `\bmemcpy_s\s*\(`,
			ObjectType:  "",
			MethodName:  "memcpy_s",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "C11 bounds-checked memory copy (prevents buffer overflow)",
		},

		// --- Path validation ---
		{
			ID:          "c.path.basename",
			Language:    rules.LangC,
			Pattern:     `\bbasename\s*\(`,
			ObjectType:  "",
			MethodName:  "basename",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract base filename (strips directory traversal)",
		},
	}
}
