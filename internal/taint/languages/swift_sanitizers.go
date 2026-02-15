package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (c *SwiftCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Data Protection API ---
		{
			ID:          "swift.data.protection",
			Language:    rules.LangSwift,
			Pattern:     `\.completeFileProtection|\.completeFileProtectionUnlessOpen|FileProtectionType`,
			ObjectType:  "",
			MethodName:  "FileProtectionType",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkCrypto},
			Description: "iOS Data Protection API for file encryption at rest",
		},

		// --- Secure Keychain ACL ---
		{
			ID:          "swift.keychain.secure.access",
			Language:    rules.LangSwift,
			Pattern:     `kSecAttrAccessibleWhenUnlocked\b|kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly\b|kSecAttrAccessibleWhenUnlockedThisDeviceOnly\b`,
			ObjectType:  "Security",
			MethodName:  "kSecAttrAccessibleWhenUnlocked",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Secure Keychain accessibility setting",
		},

		// --- Encryption ---
		{
			ID:          "swift.security.encrypt",
			Language:    rules.LangSwift,
			Pattern:     `SecKeyCreateEncryptedData\(|CryptoKit\.AES\.GCM\.seal\(|AES\.GCM\.seal\(`,
			ObjectType:  "",
			MethodName:  "SecKeyCreateEncryptedData/AES.GCM.seal",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkFileWrite},
			Description: "Apple Security framework or CryptoKit encryption",
		},

		// --- URL Validation ---
		{
			ID:          "swift.url.validation",
			Language:    rules.LangSwift,
			Pattern:     `URL\(\s*string:.*\)\s*!=\s*nil|guard\s+let\s+url\s*=\s*URL\(|if\s+let\s+url\s*=\s*URL\(`,
			ObjectType:  "",
			MethodName:  "URL validation",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL construction with nil check validates URL format",
		},

		// --- Input sanitization ---
		{
			ID:          "swift.string.addingpercentencoding",
			Language:    rules.LangSwift,
			Pattern:     `\.addingPercentEncoding\(\s*withAllowedCharacters:`,
			ObjectType:  "String",
			MethodName:  "addingPercentEncoding",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL percent encoding for safe URL construction",
		},

		// --- SQLite parameterized queries ---
		{
			ID:          "swift.sqlite3.bind",
			Language:    rules.LangSwift,
			Pattern:     `sqlite3_bind_(?:text|int|double|blob|int64)\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_bind_*",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "SQLite parameterized query binding (prevents SQL injection)",
		},

		// --- Integer conversion ---
		{
			ID:          "swift.int.init",
			Language:    rules.LangSwift,
			Pattern:     `Int\(\s*\w+\s*\)|Int\(\s*\w+\s*,\s*radix:`,
			ObjectType:  "",
			MethodName:  "Int(_:)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Integer conversion restricts to numeric values",
		},

		// --- Allowlist check ---
		{
			ID:          "swift.contains.check",
			Language:    rules.LangSwift,
			Pattern:     `allowedHosts\.contains\(|allowlist\.contains\(|whitelist\.contains\(`,
			ObjectType:  "",
			MethodName:  "allowlist.contains",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "Allowlist validation for URLs/hosts",
		},

		// --- Hashing ---
		{
			ID:          "swift.cryptokit.hash",
			Language:    rules.LangSwift,
			Pattern:     `SHA256\.hash\(|SHA384\.hash\(|SHA512\.hash\(`,
			ObjectType:  "",
			MethodName:  "SHA256/384/512.hash",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "CryptoKit secure hashing",
		},

		// --- HTML escaping ---
		{
			ID:          "swift.string.xmlescape",
			Language:    rules.LangSwift,
			Pattern:     `\.replacingOccurrences\(of:\s*"<".*"&lt;"`,
			ObjectType:  "String",
			MethodName:  "XML/HTML escaping",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "Manual HTML entity escaping",
		},

		// --- Vapor Leaf auto-escaping ---
		{
			ID:          "swift.leaf.autoescape",
			Language:    rules.LangSwift,
			Pattern:     `LeafRenderer|\.leaf\s*\(`,
			ObjectType:  "Leaf",
			MethodName:  "LeafRenderer",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Leaf template engine with auto-escaping",
		},

		// --- GRDB parameterized queries ---
		{
			ID:          "swift.grdb.statement",
			Language:    rules.LangSwift,
			Pattern:     `Statement\(\s*sql:.*arguments:|\.arguments\s*=\s*StatementArguments`,
			ObjectType:  "GRDB",
			MethodName:  "Statement with arguments",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "GRDB parameterized SQL statement",
		},
		{
			ID:          "swift.fmdb.parameterized",
			Language:    rules.LangSwift,
			Pattern:     `\.executeQuery\s*\([^,]+,\s*withArgumentsIn:|\.executeUpdate\s*\([^,]+,\s*withArgumentsIn:`,
			ObjectType:  "FMDatabase",
			MethodName:  "executeQuery withArgumentsIn",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "FMDB parameterized query with argument binding",
		},

		// --- NSRegularExpression validation ---
		{
			ID:          "swift.nsregularexpression",
			Language:    rules.LangSwift,
			Pattern:     `NSRegularExpression\(.*\)\.matches\(|NSPredicate\(format:\s*"SELF MATCHES`,
			ObjectType:  "NSRegularExpression",
			MethodName:  "matches/NSPredicate MATCHES",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Regex-based input validation",
		},

		// --- Secure Keychain archiver ---
		{
			ID:          "swift.nskeyedarchiver.secure",
			Language:    rules.LangSwift,
			Pattern:     `NSKeyedUnarchiver\.unarchivedObject\(\s*ofClass:|requiresSecureCoding\s*=\s*true`,
			ObjectType:  "NSKeyedUnarchiver",
			MethodName:  "unarchivedObject(ofClass:)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Secure coding validation for deserialization",
		},

		// --- Double conversion ---
		{
			ID:          "swift.double.init",
			Language:    rules.LangSwift,
			Pattern:     `Double\(\s*\w+\s*\)|Float\(\s*\w+\s*\)`,
			ObjectType:  "",
			MethodName:  "Double(_:)/Float(_:)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Floating-point conversion restricts to numeric values",
		},

		// --- Path canonicalization ---
		{
			ID:          "swift.url.standardized",
			Language:    rules.LangSwift,
			Pattern:     `\.standardizedFileURL|\.standardized\b|\.resolvingSymlinksInPath\b`,
			ObjectType:  "URL",
			MethodName:  "standardizedFileURL/resolvingSymlinksInPath",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite},
			Description: "URL standardization and symlink resolution (path traversal prevention)",
		},

		// --- Numeric conversion ---
		{
			ID:          "swift.double.init.string",
			Language:    rules.LangSwift,
			Pattern:     `Double\s*\(|Float\s*\(|Int\s*\(`,
			ObjectType:  "",
			MethodName:  "Double/Float/Int init",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Swift numeric type initialization from string (restricts to numeric values)",
		},
	}
}
