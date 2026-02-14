package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (c *KotlinCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- SQL Parameterization ---
		{
			ID:          "kotlin.preparedstatement",
			Language:    rules.LangKotlin,
			Pattern:     `prepareStatement\s*\(|PreparedStatement`,
			ObjectType:  "PreparedStatement",
			MethodName:  "prepareStatement",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Parameterized SQL query via PreparedStatement",
		},
		{
			ID:          "kotlin.android.selectionargs",
			Language:    rules.LangKotlin,
			Pattern:     `rawQuery\s*\([^,]+,\s*arrayOf\s*\(`,
			ObjectType:  "SQLiteDatabase",
			MethodName:  "rawQuery with selectionArgs",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Android rawQuery with parameterized selection args",
		},
		{
			ID:          "kotlin.room.dao",
			Language:    rules.LangKotlin,
			Pattern:     `@(?:Query|Insert|Update|Delete)`,
			ObjectType:  "Room",
			MethodName:  "Room DAO annotation",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Room DAO parameterized queries",
		},
		{
			ID:          "kotlin.exposed.parameterized",
			Language:    rules.LangKotlin,
			Pattern:     `\.select\s*\{|\.selectAll\s*\(|\.where\s*\{`,
			ObjectType:  "Exposed",
			MethodName:  "Exposed DSL query",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Jetbrains Exposed DSL parameterized queries",
		},

		// --- HTML Encoding ---
		{
			ID:          "kotlin.html.escapehtml",
			Language:    rules.LangKotlin,
			Pattern:     `Html\.escapeHtml\s*\(|TextUtils\.htmlEncode\s*\(`,
			ObjectType:  "",
			MethodName:  "Html.escapeHtml/TextUtils.htmlEncode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Android HTML entity escaping",
		},
		{
			ID:          "kotlin.spring.htmlutils",
			Language:    rules.LangKotlin,
			Pattern:     `HtmlUtils\.htmlEscape\s*\(`,
			ObjectType:  "HtmlUtils",
			MethodName:  "htmlEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Spring HTML entity escaping",
		},

		// --- URL Encoding ---
		{
			ID:          "kotlin.urlencoder.encode",
			Language:    rules.LangKotlin,
			Pattern:     `URLEncoder\.encode\s*\(`,
			ObjectType:  "URLEncoder",
			MethodName:  "encode",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "URL encoding",
		},

		// --- Input Validation ---
		{
			ID:          "kotlin.regex.matches",
			Language:    rules.LangKotlin,
			Pattern:     `\.matches\s*\(|Regex\s*\(.*\)\.matches`,
			ObjectType:  "Regex",
			MethodName:  "matches",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Regex validation restricts input to safe patterns",
		},
		{
			ID:          "kotlin.require",
			Language:    rules.LangKotlin,
			Pattern:     `require\s*\(|check\s*\(`,
			ObjectType:  "",
			MethodName:  "require/check",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Kotlin precondition check",
		},

		// --- Type Coercion ---
		{
			ID:          "kotlin.toint",
			Language:    rules.LangKotlin,
			Pattern:     `\.toInt\s*\(|\.toLong\s*\(|\.toIntOrNull\s*\(|\.toLongOrNull\s*\(`,
			ObjectType:  "",
			MethodName:  "toInt/toLong",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Integer conversion restricts to numeric values",
		},

		// --- Path Traversal Prevention ---
		{
			ID:          "kotlin.file.name",
			Language:    rules.LangKotlin,
			Pattern:     `\.name\b|File\(.*\)\.name`,
			ObjectType:  "File",
			MethodName:  "name",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Extract filename only (strips directory components)",
		},
		{
			ID:          "kotlin.path.normalize",
			Language:    rules.LangKotlin,
			Pattern:     `\.normalize\s*\(|\.canonicalPath|\.canonicalFile`,
			ObjectType:  "Path/File",
			MethodName:  "normalize/canonicalPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "Path normalization prevents traversal",
		},

		// --- Cryptography ---
		{
			ID:          "kotlin.bcrypt",
			Language:    rules.LangKotlin,
			Pattern:     `BCrypt\.hashpw\s*\(|BCryptPasswordEncoder`,
			ObjectType:  "",
			MethodName:  "BCrypt.hashpw",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "bcrypt password hashing",
		},

		// --- Spring Validation ---
		{
			ID:          "kotlin.spring.valid",
			Language:    rules.LangKotlin,
			Pattern:     `@Valid\b|@Validated\b`,
			ObjectType:  "Spring",
			MethodName:  "@Valid/@Validated",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Spring Bean Validation",
		},

		// --- Ktor Input Validation ---
		{
			ID:          "kotlin.ktor.receivewithvalidation",
			Language:    rules.LangKotlin,
			Pattern:     `call\.receive.*\.validate\s*\(|RequestValidationConfig`,
			ObjectType:  "Ktor",
			MethodName:  "receive with validation",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Ktor request validation plugin",
		},

		// --- Android EncryptedSharedPreferences ---
		{
			ID:          "kotlin.android.encryptedsharedprefs",
			Language:    rules.LangKotlin,
			Pattern:     `EncryptedSharedPreferences\.create\s*\(`,
			ObjectType:  "EncryptedSharedPreferences",
			MethodName:  "create",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Android EncryptedSharedPreferences for secure storage",
		},
	}
}
