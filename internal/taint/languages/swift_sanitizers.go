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
	}
}
