package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
		// ObjectType is "" (not "String"): a String value is held in a variable
		// named `input`/`name`/`safe` — never `String` — so the prior ObjectType
		// "String" never matched any real receiver and the sanitizer was DEAD
		// (the matcher has no "string"-receiver heuristic). The method name
		// `addingPercentEncoding(withAllowedCharacters:)` is itself the
		// sanitizing operation — every call percent-encodes the value — so a
		// wildcard ObjectType with the call-anchored Pattern is precise: it
		// matches exactly the percent-encoding call and nothing else. This pairs
		// the HTML-output sanitizer with the Vapor Response XSS sink so the
		// percent-encoded-then-rendered safe form does not false-positive.
		{
			ID:          "swift.string.addingpercentencoding",
			Language:    rules.LangSwift,
			Pattern:     `\.addingPercentEncoding\(\s*withAllowedCharacters:`,
			ObjectType:  "",
			MethodName:  "addingPercentEncoding",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL/HTML percent encoding for safe URL construction and output encoding",
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
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

		// --- Fixed-width & unsigned integer / wide-float coercion (CWE-89/78/943) ---
		// Swift's failable numeric initializers (Int64(str), UInt(str), Float32(str), ...)
		// constrain user input to a provably-numeric value that cannot carry SQL/command/
		// path/NoSQL/LDAP/XPath metacharacters. The existing swift.int.init / swift.double.init
		// entries use a "(_:)" MethodName that the tsflow matcher cannot resolve (the ":" is
		// normalized to "." so the final method segment becomes ")"), so the fixed-width and
		// unsigned families had no working coverage. Bare type-name MethodNames match the
		// call_expression callee directly. Neutralizes mirrors the csharp.int.parse precedent.
		{
			ID:          "swift.int8.init",
			Language:    rules.LangSwift,
			Pattern:     `\bInt8\s*\(`,
			ObjectType:  "",
			MethodName:  "Int8",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "Int8 conversion restricts user input to a numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.int16.init",
			Language:    rules.LangSwift,
			Pattern:     `\bInt16\s*\(`,
			ObjectType:  "",
			MethodName:  "Int16",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "Int16 conversion restricts user input to a numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.int32.init",
			Language:    rules.LangSwift,
			Pattern:     `\bInt32\s*\(`,
			ObjectType:  "",
			MethodName:  "Int32",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "Int32 conversion restricts user input to a numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.int64.init",
			Language:    rules.LangSwift,
			Pattern:     `\bInt64\s*\(`,
			ObjectType:  "",
			MethodName:  "Int64",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "Int64 conversion restricts user input to a numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.uint.init",
			Language:    rules.LangSwift,
			Pattern:     `\bUInt\s*\(`,
			ObjectType:  "",
			MethodName:  "UInt",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "UInt conversion restricts user input to an unsigned numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.uint8.init",
			Language:    rules.LangSwift,
			Pattern:     `\bUInt8\s*\(`,
			ObjectType:  "",
			MethodName:  "UInt8",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "UInt8 conversion restricts user input to an unsigned numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.uint16.init",
			Language:    rules.LangSwift,
			Pattern:     `\bUInt16\s*\(`,
			ObjectType:  "",
			MethodName:  "UInt16",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "UInt16 conversion restricts user input to an unsigned numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.uint32.init",
			Language:    rules.LangSwift,
			Pattern:     `\bUInt32\s*\(`,
			ObjectType:  "",
			MethodName:  "UInt32",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "UInt32 conversion restricts user input to an unsigned numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.uint64.init",
			Language:    rules.LangSwift,
			Pattern:     `\bUInt64\s*\(`,
			ObjectType:  "",
			MethodName:  "UInt64",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "UInt64 conversion restricts user input to an unsigned numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.float32.init",
			Language:    rules.LangSwift,
			Pattern:     `\bFloat32\s*\(`,
			ObjectType:  "",
			MethodName:  "Float32",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "Float32 conversion restricts user input to a numeric value (no injectable metacharacters)",
		},
		{
			ID:          "swift.float64.init",
			Language:    rules.LangSwift,
			Pattern:     `\bFloat64\s*\(`,
			ObjectType:  "",
			MethodName:  "Float64",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkNoSQL, taint.SnkLDAP, taint.SnkXPath},
			Description: "Float64 conversion restricts user input to a numeric value (no injectable metacharacters)",
		},

		// --- NSPredicate parameterized (prevents predicate injection) ---
		{
			ID:          "swift.nspredicate.argumentarray",
			Language:    rules.LangSwift,
			Pattern:     `NSPredicate\(\s*format:.*argumentArray:|NSPredicate\(\s*format:.*,\s*\w+\)`,
			ObjectType:  "NSPredicate",
			MethodName:  "NSPredicate(format:argumentArray:)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "NSPredicate with parameterized arguments prevents injection",
		},

		// --- URLComponents safe construction ---
		{
			ID:          "swift.urlcomponents.safe",
			Language:    rules.LangSwift,
			Pattern:     `URLComponents\(\s*string:.*\.queryItems\s*=\s*\[URLQueryItem`,
			ObjectType:  "URLComponents",
			MethodName:  "URLComponents.queryItems",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URLComponents with URLQueryItem properly encodes query parameters",
		},

		// --- Swift Regex (5.7+) ---
		{
			ID:          "swift.regex.match",
			Language:    rules.LangSwift,
			Pattern:     `\.wholeMatch\(\s*of:|\.firstMatch\(\s*of:|\.matches\(\s*of:`,
			ObjectType:  "Regex",
			MethodName:  "wholeMatch(of:)/firstMatch(of:)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Swift Regex validation (type-safe, compile-time checked)",
		},

		// --- Fluent parameterized query ---
		{
			ID:          "swift.fluent.filter",
			Language:    rules.LangSwift,
			Pattern:     `\.filter\(\s*\\\.`,
			ObjectType:  "Fluent",
			MethodName:  "filter(\\.field ==)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Fluent ORM type-safe filter uses parameterized queries",
		},

		// --- URL host validation ---
		{
			ID:          "swift.url.host.check",
			Language:    rules.LangSwift,
			Pattern:     `\.host\s*==\s*"|\.host\(\)\s*==\s*"|allowedHosts\.contains\(.*\.host`,
			ObjectType:  "URL",
			MethodName:  "url.host == / allowedHosts.contains",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL host validation against expected domain",
		},

		// --- Data base64 encoding (neutralizes raw binary concerns) ---
		{
			ID:          "swift.data.base64",
			Language:    rules.LangSwift,
			Pattern:     `\.base64EncodedString\(|\.base64EncodedData\(`,
			ObjectType:  "Data",
			MethodName:  "base64EncodedString()",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkLog},
			Description: "Base64 encoding produces safe alphanumeric output",
		},

		// --- URL scheme validation ---
		{
			ID:          "swift.url.scheme.check",
			Language:    rules.LangSwift,
			Pattern:     `\.scheme\s*==\s*"https"|\.scheme\s*==\s*"http"`,
			ObjectType:  "URL",
			MethodName:  "url.scheme == \"https\"",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL scheme validation restricts to HTTP(S)",
		},

		// --- Process with array arguments (prevents shell injection) ---
		{
			ID:          "swift.process.array.arguments",
			Language:    rules.LangSwift,
			Pattern:     `\.arguments\s*=\s*\[`,
			ObjectType:  "Process",
			MethodName:  "arguments = [...]",
			Neutralizes: []taint.SinkCategory{taint.SnkCommand},
			Description: "Process with array arguments avoids shell interpretation",
		},

		// --- os_log privacy annotations ---
		{
			ID:          "swift.oslog.privacy",
			Language:    rules.LangSwift,
			Pattern:     `privacy:\s*\.private\b|privacy:\s*\.sensitive\b|OSLogPrivacy\.private|OSLogPrivacy\.sensitive`,
			ObjectType:  "OSLog",
			MethodName:  "OSLogPrivacy.private/sensitive",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "os_log privacy annotation redacts sensitive data from logs",
		},

		// --- Logger with privacy metadata ---
		{
			ID:          "swift.logger.privacy.interpolation",
			Language:    rules.LangSwift,
			Pattern:     `\\\(\s*\w+\s*,\s*privacy:\s*\.`,
			ObjectType:  "Logger",
			MethodName:  "\\(value, privacy: .private)",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "Swift Logger string interpolation with privacy annotation",
		},

		// --- JSON content-type response (not rendered as HTML) ---
		{
			ID:          "swift.vapor.response.json",
			Language:    rules.LangSwift,
			Pattern:     `\.json\s*\(|\.encodeResponse\(\s*for:.*\.json|Content-Type.*application/json`,
			ObjectType:  "Response",
			MethodName:  "response.json()",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput},
			Description: "JSON response content-type prevents browser HTML rendering",
		},

		// --- Codable type-safe deserialization ---
		{
			ID:          "swift.codable.decode",
			Language:    rules.LangSwift,
			Pattern:     `\.decode\(\s*\w+\.self\s*,\s*from:`,
			ObjectType:  "JSONDecoder",
			MethodName:  "decode(T.self, from:)",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "Codable type-safe deserialization constrains output to known types",
		},

		// --- Container URL sandbox check ---
		{
			ID:          "swift.filemanager.containerurl",
			Language:    rules.LangSwift,
			Pattern:     `FileManager\.default\.containerURL\(\s*forSecurityApplicationGroupIdentifier:`,
			ObjectType:  "FileManager",
			MethodName:  "containerURL(forSecurityApplicationGroupIdentifier:)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "App container URL provides sandboxed path root",
		},

		// --- Path starts-with containment check ---
		{
			ID:          "swift.path.hasprefix.check",
			Language:    rules.LangSwift,
			Pattern:     `\.hasPrefix\(\s*(?:documentsDir|baseDir|sandboxDir|containerPath|allowedPath)`,
			ObjectType:  "String",
			MethodName:  "path.hasPrefix(baseDir)",
			Neutralizes: []taint.SinkCategory{taint.SnkFileWrite, taint.SnkFileRead},
			Description: "Path containment check using hasPrefix against known base directory",
		},

		// --- HTTP header value encoding ---
		{
			ID:          "swift.header.value.encoding",
			Language:    rules.LangSwift,
			Pattern:     `\.replacingOccurrences\(of:\s*"\\r\\n".*""|\.replacingOccurrences\(of:\s*"\\n".*""`,
			ObjectType:  "String",
			MethodName:  "header value CRLF stripping",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Stripping CRLF from header values prevents header injection",
		},

		// --- String prefix/suffix for URL scheme ---
		{
			ID:          "swift.string.hasprefix.https",
			Language:    rules.LangSwift,
			Pattern:     `\.hasPrefix\(\s*"https://"|\.hasPrefix\(\s*"http://"`,
			ObjectType:  "String",
			MethodName:  "hasPrefix(\"https://\")",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkRedirect},
			Description: "URL string prefix check constrains to HTTP(S) scheme",
		},

		// --- CharacterSet URL encoding ---
		{
			ID:          "swift.characterset.urlencode",
			Language:    rules.LangSwift,
			Pattern:     `\.addingPercentEncoding\(\s*withAllowedCharacters:\s*\.urlQueryAllowed|\.addingPercentEncoding\(\s*withAllowedCharacters:\s*\.urlPathAllowed`,
			ObjectType:  "String",
			MethodName:  "addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch, taint.SnkHeader},
			Description: "URL percent encoding with standard CharacterSet for query/path safety",
		},

		// --- Vapor abort for validation ---
		{
			ID:          "swift.vapor.abort",
			Language:    rules.LangSwift,
			Pattern:     `throw\s+Abort\(\s*\.badRequest|throw\s+Abort\(\s*\.forbidden|throw\s+Abort\(\s*\.unauthorized`,
			ObjectType:  "Abort",
			MethodName:  "throw Abort(.badRequest)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput, taint.SnkFileWrite, taint.SnkURLFetch},
			Description: "Vapor Abort thrown on validation failure terminates request processing",
		},

		// --- guard let with return/throw (early exit pattern) ---
		{
			ID:          "swift.guard.let.validation",
			Language:    rules.LangSwift,
			Pattern:     `guard\s+let\s+\w+\s*=\s*Int\(|guard\s+let\s+\w+\s*=\s*UUID\(`,
			ObjectType:  "",
			MethodName:  "guard let x = Int(input)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand},
			Description: "Guard-let with type conversion validates input or exits early",
		},

		// --- HMAC/signature verification ---
		{
			ID:          "swift.cryptokit.hmac.verify",
			Language:    rules.LangSwift,
			Pattern:     `HMAC<SHA256>\.isValidAuthenticationCode\(|HMAC\.isValidAuthenticationCode\(`,
			ObjectType:  "HMAC",
			MethodName:  "HMAC.isValidAuthenticationCode",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "HMAC verification ensures data integrity before processing",
		},

		// --- Alamofire ServerTrustManager (certificate pinning) ---
		{
			ID:          "swift.alamofire.servertrustmanager",
			Language:    rules.LangSwift,
			Pattern:     `ServerTrustManager\s*\(|PinnedCertificatesTrustEvaluator\s*\(|PublicKeysTrustEvaluator\s*\(`,
			ObjectType:  "Alamofire",
			MethodName:  "ServerTrustManager",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Alamofire certificate pinning restricts connections to trusted servers",
		},

		// --- Alamofire RequestInterceptor (URL validation) ---
		{
			ID:          "swift.alamofire.requestinterceptor",
			Language:    rules.LangSwift,
			Pattern:     `RequestInterceptor|RequestAdapter|\.adapt\s*\(\s*[^;{]*urlRequest`,
			ObjectType:  "Alamofire",
			MethodName:  "RequestInterceptor/adapt",
			Neutralizes: []taint.SinkCategory{taint.SnkURLFetch},
			Description: "Alamofire request interceptor can enforce URL allowlists",
		},

		// --- Alamofire URLEncodedFormParameterEncoder (auto-encodes params) ---
		{
			ID:          "swift.alamofire.parameterencoder",
			Language:    rules.LangSwift,
			Pattern:     `URLEncodedFormParameterEncoder\s*\(|JSONParameterEncoder\s*\(`,
			ObjectType:  "Alamofire",
			MethodName:  "URLEncodedFormParameterEncoder/JSONParameterEncoder",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkHeader},
			Description: "Alamofire parameter encoders properly encode values for transport",
		},

		// --- Secure random (neutralizes weak PRNG concerns) ---
		{
			ID:          "swift.securerandom.arc4random",
			Language:    rules.LangSwift,
			Pattern:     `arc4random_uniform\s*\(|arc4random\s*\(|arc4random_buf\s*\(`,
			ObjectType:  "",
			MethodName:  "arc4random/arc4random_uniform",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "arc4random family uses AES-CTR CSPRNG (secure since macOS 10.12/iOS 10)",
		},
		{
			ID:          "swift.securerandom.systemrng",
			Language:    rules.LangSwift,
			Pattern:     `SystemRandomNumberGenerator\s*\(|\.random\(\s*in:`,
			ObjectType:  "",
			MethodName:  "SystemRandomNumberGenerator / Int.random(in:)",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Swift SystemRandomNumberGenerator backed by arc4random_buf (CSPRNG)",
		},
		{
			ID:          "swift.securerandom.secrandomcopybytes",
			Language:    rules.LangSwift,
			Pattern:     `SecRandomCopyBytes\s*\(`,
			ObjectType:  "Security",
			MethodName:  "SecRandomCopyBytes",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Apple Security framework CSPRNG",
		},

		// --- TLS certificate pinning (neutralizes TLS bypass) ---
		{
			ID:          "swift.tls.pinning.evaluatewitherror",
			Language:    rules.LangSwift,
			Pattern:     `SecTrustEvaluateWithError\s*\(`,
			ObjectType:  "Security",
			MethodName:  "SecTrustEvaluateWithError",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "Proper TLS trust evaluation with error checking",
		},
		{
			ID:          "swift.tls.pinning.publickeys",
			Language:    rules.LangSwift,
			Pattern:     `SecTrustCopyPublicKey\s*\(|pinnedCertificates|pinnedPublicKeys`,
			ObjectType:  "Security",
			MethodName:  "Certificate/public key pinning",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "TLS certificate or public key pinning prevents MITM",
		},

		// --- XXE prevention ---
		{
			ID:          "swift.xmlparser.xxe.disabled",
			Language:    rules.LangSwift,
			Pattern:     `shouldResolveExternalEntities\s*=\s*false`,
			ObjectType:  "XMLParser",
			MethodName:  "shouldResolveExternalEntities = false",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "XMLParser external entity resolution explicitly disabled (XXE prevention)",
		},

		// --- Bounds checking for unsafe memory ---
		{
			ID:          "swift.unsafe.precondition",
			Language:    rules.LangSwift,
			Pattern:     `precondition\(\s*\w+\s*<\s*\w+|precondition\(\s*\w+\s*<=\s*\w+|guard\s+\w+\s*<\s*capacity`,
			ObjectType:  "",
			MethodName:  "precondition(index < count)",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Bounds checking precondition/guard before unsafe memory access",
		},

		// --- Trust boundary: local-only pasteboard ---
		{
			ID:          "swift.pasteboard.localonly",
			Language:    rules.LangSwift,
			Pattern:     `\.localOnly\s*:\s*true|UIPasteboard\.withLocalOnly`,
			ObjectType:  "UIPasteboard",
			MethodName:  "localOnly: true",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Pasteboard local-only flag prevents cross-device clipboard sharing",
		},

		// --- Trust boundary: exclude activity types ---
		{
			ID:          "swift.uiactivity.excludedtypes",
			Language:    rules.LangSwift,
			Pattern:     `excludedActivityTypes\s*=`,
			ObjectType:  "UIActivityViewController",
			MethodName:  "excludedActivityTypes",
			Neutralizes: []taint.SinkCategory{taint.SnkTrustBoundary},
			Description: "Restricting share sheet activity types limits data exposure",
		},

		// --- Path canonicalization for file read ---
		{
			ID:          "swift.url.standardized.fileread",
			Language:    rules.LangSwift,
			Pattern:     `\.standardizedFileURL\.path\.hasPrefix\(|\.resolvingSymlinksInPath\(\)\.hasPrefix\(`,
			ObjectType:  "URL",
			MethodName:  "standardizedFileURL.path.hasPrefix",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead},
			Description: "Path canonicalization + prefix check prevents path traversal on file reads",
		},

		// --- Realm type-safe filter (keypaths) ---
		{
			ID:          "swift.realm.filter.keypath",
			Language:    rules.LangSwift,
			Pattern:     `\.filter\(\s*\\\.`,
			ObjectType:  "Realm",
			MethodName:  "filter(\\.keypath ==)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Realm type-safe keypath filter prevents predicate injection",
		},

		// --- XPath parameterization ---
		{
			ID:       "swift.xpath.escaping",
			Language: rules.LangSwift,
			Pattern:  `\.replacingOccurrences\(of:\s*"'".*"&apos;"`,
			// @argpattern: matched by the call text Pattern, keyed under the
			// method name `replacingOccurrences`. The previous prose MethodName
			// ("XPath string escaping") keyed this entry under the dead token
			// "escaping", so it never matched the `query.replacingOccurrences(
			// of: "'", with: "&apos;")` call and the sanitizer was inert.
			ObjectType:  "@argpattern",
			MethodName:  "replacingOccurrences",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XPath value escaping prevents injection via single-quote replacement",
		},
		{
			ID:          "swift.xpath.cfxml.escape",
			Language:    rules.LangSwift,
			Pattern:     `CFXMLCreateStringByEscapingEntities\s*\(`,
			ObjectType:  "",
			MethodName:  "CFXMLCreateStringByEscapingEntities",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Core Foundation XML entity escaping converts <, >, &, ', \" to safe entity references",
		},
		{
			ID:          "swift.xpath.xmlnode.text",
			Language:    rules.LangSwift,
			Pattern:     `XMLNode\(\s*kind:\s*\.text`,
			ObjectType:  "XMLNode",
			MethodName:  "XMLNode(kind: .text)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "Constructing XMLNode text nodes auto-escapes special characters, preventing XPath injection via DOM API",
		},

		// --- LDAP filter escaping ---
		{
			ID:          "swift.ldap.filter.escape",
			Language:    rules.LangSwift,
			Pattern:     `\.replacingOccurrences\(of:\s*"[\\\\(*)]".*"\\\\[0-9a-f]{2}"`,
			ObjectType:  "",
			MethodName:  "replacingOccurrences",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Manual LDAP filter character escaping (RFC 4515 hex encoding)",
		},

		// --- MongoDB typed query builders (NoSQL injection prevention) ---
		{
			ID:          "swift.mongoswift.bsondocument.literal",
			Language:    rules.LangSwift,
			Pattern:     `BSONDocument\s*\(|let\s+\w+\s*:\s*BSONDocument\s*=\s*\[`,
			ObjectType:  "MongoSwift.BSONDocument",
			MethodName:  "BSONDocument literal",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MongoSwift typed BSONDocument literal enforces structured queries",
		},
		{
			ID:          "swift.mongokitten.mongoqueryfilter",
			Language:    rules.LangSwift,
			Pattern:     `MongoKitten\.QueryFilter|\.where\(\s*"[^"]+"\s*==`,
			ObjectType:  "MongoKitten",
			MethodName:  "QueryFilter / type-safe where",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MongoKitten type-safe query filters prevent NoSQL injection",
		},
		{
			ID:          "swift.mongodb.input.int.conversion",
			Language:    rules.LangSwift,
			Pattern:     `ObjectId\s*\(\s*\w+\s*\)|BSONObjectID\s*\(\s*\w+\s*\)`,
			ObjectType:  "BSONObjectID",
			MethodName:  "ObjectId/BSONObjectID",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Converting input to ObjectId/BSONObjectID constrains to valid 24-hex-char ID",
		},

		// --- MySQLNIO parameterized query (CWE-89) ---
		{
			ID:          "swift.mysqlnio.query.bindings",
			Language:    rules.LangSwift,
			Pattern:     `\.query\s*\(\s*"[^"]*"\s*,\s*\[`,
			ObjectType:  "MySQLConnection",
			MethodName:  "query",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "MySQLNIO parameterized query with bindings array prevents SQL injection",
		},

		// --- Vapor FileIO path sanitization ---
		{
			ID:          "swift.vapor.directory.publicdirectory",
			Language:    rules.LangSwift,
			Pattern:     `app\.directory\.publicDirectory|app\.directory\.workingDirectory`,
			ObjectType:  "Application",
			MethodName:  "directory.publicDirectory",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Vapor public/working directory prefix used for path anchoring prevents traversal",
		},
		{
			ID:          "swift.url.lastpathcomponent",
			Language:    rules.LangSwift,
			Pattern:     `\.lastPathComponent\b`,
			ObjectType:  "URL",
			MethodName:  "lastPathComponent",
			Neutralizes: []taint.SinkCategory{taint.SnkFileRead, taint.SnkFileWrite},
			Description: "Extracting lastPathComponent strips directory traversal sequences",
		},

		// --- swift-log structured metadata (log injection prevention) ---
		{
			ID:          "swift.swiftlog.metadata",
			Language:    rules.LangSwift,
			Pattern:     `Logger\.MetadataValue\.string\(|Logger\.Metadata\(|\.metadata\s*=\s*\[`,
			ObjectType:  "",
			MethodName:  "MetadataValue.string/Metadata",
			Neutralizes: []taint.SinkCategory{taint.SnkLog},
			Description: "swift-log structured metadata encoding prevents log injection by serializing values as typed key-value pairs",
		},

		// --- Newline/control character filtering (log injection prevention) ---
		{
			ID:          "swift.string.filter.newlines",
			Language:    rules.LangSwift,
			Pattern:     `\.filter\s*\{.*isNewline|\.replacingOccurrences\(of:\s*"\\n"\s*,\s*with:\s*""`,
			ObjectType:  "",
			MethodName:  "filter/replacingOccurrences",
			Neutralizes: []taint.SinkCategory{taint.SnkLog, taint.SnkHeader},
			Description: "Filtering or replacing newline characters prevents log and header injection",
		},

		// --- Secure deserialization (NSSecureCoding) ---
		{
			ID:          "swift.nssecurecoding.conformance",
			Language:    rules.LangSwift,
			Pattern:     `NSSecureCoding|supportsSecureCoding\s*=\s*true`,
			ObjectType:  "NSSecureCoding",
			MethodName:  "NSSecureCoding conformance",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize},
			Description: "NSSecureCoding protocol enforces type-safe deserialization",
		},

		// =====================================================================
		// Eval sanitizers (CWE-95) — safe alternatives to NSExpression(format:),
		// evaluateJavaScript, and NSRegularExpression with user patterns
		// =====================================================================

		// --- NSExpression safe constructors ---
		{
			ID:          "swift.nsexpression.forconstantvalue",
			Language:    rules.LangSwift,
			Pattern:     `NSExpression\(\s*forConstantValue:`,
			ObjectType:  "NSExpression",
			MethodName:  "NSExpression",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "NSExpression(forConstantValue:) creates a constant expression that cannot invoke ObjC runtime methods via FUNCTION keyword",
		},
		{
			ID:          "swift.nsexpression.forkeypath",
			Language:    rules.LangSwift,
			Pattern:     `NSExpression\(\s*forKeyPath:`,
			ObjectType:  "NSExpression",
			MethodName:  "NSExpression",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "NSExpression(forKeyPath:) restricts to property access, cannot invoke arbitrary methods",
		},

		// --- Swift 5.9+ type-safe #Predicate macro ---
		{
			ID:          "swift.predicate.macro",
			Language:    rules.LangSwift,
			Pattern:     `#Predicate\s*[<{]`,
			ObjectType:  "",
			MethodName:  "#Predicate",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Swift 5.9+ #Predicate macro is compile-time type-checked, eliminates format-string injection",
		},

		// --- WKWebView safe eval alternative ---
		{
			ID:          "swift.wkwebview.callasyncjavascript",
			Language:    rules.LangSwift,
			Pattern:     `\.callAsyncJavaScript\s*\(`,
			ObjectType:  "WKWebView",
			MethodName:  "callAsyncJavaScript",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "WKWebView.callAsyncJavaScript passes data via arguments dictionary, not as evaluated code",
		},

		// --- JavaScriptCore safe data passing ---
		{
			ID:          "swift.jscontext.setobject",
			Language:    rules.LangSwift,
			Pattern:     `\.setObject\s*\([^)]*forKeyedSubscript:`,
			ObjectType:  "JSContext",
			MethodName:  "setObject",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "JSContext.setObject passes typed values without string evaluation",
		},

		// --- Regex metacharacter escaping ---
		{
			ID:          "swift.nsregularexpression.escapedpattern",
			Language:    rules.LangSwift,
			Pattern:     `NSRegularExpression\.escapedPattern\(\s*for:`,
			ObjectType:  "NSRegularExpression",
			MethodName:  "escapedPattern",
			Neutralizes: []taint.SinkCategory{taint.SnkEval, taint.SnkRegexDoS},
			Description: "Escapes regex metacharacters in user input, prevents ReDoS and regex injection. Escaped patterns are matched literally, so an attacker-controlled string cannot introduce catastrophic-backtracking constructs (CWE-1333) — neutralizes the Regex(_:) runtime ReDoS sink.",
		},

		// =====================================================================
		// LDAP sanitizers (CWE-90) — escaping and allowlist validation for
		// LDAP filter/DN construction
		// =====================================================================

		// --- LDAP Distinguished Name escaping (RFC 2253) ---
		{
			ID:          "swift.ldap.dn.escape",
			Language:    rules.LangSwift,
			Pattern:     `\.replacingOccurrences\(of:\s*"[,+<>;=#]".*with:.*"\\\\`,
			ObjectType:  "",
			MethodName:  "replacingOccurrences",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Manual LDAP Distinguished Name character escaping per RFC 2253",
		},

		// --- Alphanumeric allowlist validation ---
		{
			ID:          "swift.ldap.allowlist.alphanumeric",
			Language:    rules.LangSwift,
			Pattern:     `CharacterSet\.alphanumerics\.isSuperset\(|\.allSatisfy\s*\{.*\.isLetter`,
			ObjectType:  "",
			MethodName:  "isSuperset/allSatisfy",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "Allowlist validation restricting input to alphanumeric characters prevents LDAP injection",
		},

		// --- Apple OpenDirectory structured record access ---
		{
			ID:          "swift.odrecord.structured",
			Language:    rules.LangSwift,
			Pattern:     `\.record\(\s*withRecordType:\s*kODRecordType|\.values\(\s*forAttribute:\s*kODAttribute`,
			ObjectType:  "ODNode",
			MethodName:  "record/values",
			Neutralizes: []taint.SinkCategory{taint.SnkLDAP},
			Description: "OpenDirectory typed record/attribute API avoids raw LDAP filter string construction",
		},

		// =====================================================================
		// Template sanitizers (CWE-1336) — auto-escaping and escape filter
		// registration for Mustache and Stencil template engines
		// =====================================================================

		// --- Mustache HTML content type (enables auto-escaping) ---
		{
			ID:          "swift.mustache.contenttype.html",
			Language:    rules.LangSwift,
			Pattern:     `\.contentType\s*=\s*\.html|contentType:\s*\.html`,
			ObjectType:  "MustacheTemplate",
			MethodName:  "contentType",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Mustache HTML content type enables auto-escaping of interpolated values in {{}} tags",
		},

		// --- Stencil custom escape filter registration ---
		{
			ID:          "swift.stencil.registerfilter.escape",
			Language:    rules.LangSwift,
			Pattern:     `registerFilter\s*\(\s*"escape|registerFilter\s*\(\s*"escapeHTML"`,
			ObjectType:  "Extension",
			MethodName:  "registerFilter",
			Neutralizes: []taint.SinkCategory{taint.SnkTemplate, taint.SnkHTMLOutput},
			Description: "Stencil custom HTML escape filter registration enables output encoding (Stencil does not auto-escape by default)",
		},

		// =====================================================================
		// Type conversion sanitizers (CWE-89/CWE-78) — UUID format restriction
		// =====================================================================

		// --- UUID string parsing ---
		// UUID(uuidString:) constrains input to valid 8-4-4-4-12 hex format.
		// Unused calls like UUID() (random) take no input so don't affect taint.
		{
			ID:          "swift.uuid.init.uuidstring",
			Language:    rules.LangSwift,
			Pattern:     `UUID\(\s*uuidString:\s*\w+`,
			ObjectType:  "",
			MethodName:  "UUID",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkTrustBoundary},
			Description: "UUID(uuidString:) constrains input to valid 8-4-4-4-12 hex format, preventing injection payloads",
		},

		// =====================================================================
		// JWT signature verification (CWE-347 sanitizer)
		// =====================================================================

		// --- SwiftJWT (Kitura) JWT.verify(_:using:) ---
		// Performs full cryptographic signature verification using the passed
		// JWTVerifier. A flow that reaches JWT.verify with a real verifier is
		// authenticated and no longer a signature-bypass risk.
		{
			ID:          "swift.jwt.kitura.verify",
			Language:    rules.LangSwift,
			Pattern:     `JWT(?:<[^>]+>)?\.verify\s*\(`,
			ObjectType:  "JWT",
			MethodName:  "verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "SwiftJWT JWT.verify(token, using: verifier) performs cryptographic signature verification against the supplied JWTVerifier",
		},

		// =====================================================================
		// Modern password verification (CWE-916, CWE-287) — adaptive password
		// hashing libraries that use unique per-record salts and constant-time
		// comparison for verification.
		// =====================================================================

		// --- Vapor BCrypt.verify(_:created:) ---
		// vapor/vapor (Sources/Vapor/Bcrypt/Bcrypt.swift) and the standalone
		// vapor-community/bcrypt package both expose `BCrypt.verify(plaintext,
		// created: hash)`. The plaintext password is at args[0] and is consumed
		// by a constant-time comparison against the stored bcrypt digest.
		{
			ID:          "swift.vapor.bcrypt.verify",
			Language:    rules.LangSwift,
			Pattern:     `BCrypt\.verify\s*\(`,
			ObjectType:  "Bcrypt",
			MethodName:  "verify",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary},
			Description: "Vapor BCrypt.verify(_:created:) performs adaptive bcrypt verification with constant-time comparison against the stored digest",
		},

		// --- Argon2Swift.verifyHashString(password:hash:) ---
		// tmthecoder/Argon2Swift exposes `Argon2Swift.verifyHashString(password:
		// String, hash: String, type: Argon2Type = .i)` which decodes the encoded
		// hash (including salt and parameters) and re-hashes the password for a
		// constant-time match. Argon2 is the modern recommended password KDF.
		{
			ID:          "swift.argon2swift.verifyhashstring",
			Language:    rules.LangSwift,
			Pattern:     `Argon2Swift\.verifyHashString\s*\(`,
			ObjectType:  "Argon2Swift",
			MethodName:  "verifyHashString",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkTrustBoundary},
			Description: "Argon2Swift.verifyHashString(password:hash:) verifies a plaintext password against an Argon2-encoded digest using constant-time comparison",
		},

		// =====================================================================
		// HTML sanitization (CWE-79) — allowlist-based and entity-encoding
		// libraries that produce safe HTML output from untrusted input.
		// =====================================================================

		// --- SwiftSoup.clean(_:_:) (Whitelist-based HTML sanitizer) ---
		// scinfu/SwiftSoup is the Swift port of jsoup. `SwiftSoup.clean(html,
		// Whitelist.basic())` parses the HTML and emits only the tags/attributes
		// permitted by the supplied whitelist; everything else (scripts, event
		// handlers, javascript: URLs) is stripped. The cleaned string is safe
		// for SnkHTMLOutput sinks like WKWebView.loadHTMLString and Vapor
		// Response bodies.
		{
			ID:          "swift.swiftsoup.clean",
			Language:    rules.LangSwift,
			Pattern:     `SwiftSoup\.clean\s*\(`,
			ObjectType:  "SwiftSoup",
			MethodName:  "clean",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "SwiftSoup.clean(html, Whitelist) sanitizes HTML against a tag/attribute allowlist (Swift port of jsoup), stripping scripts and dangerous attributes",
		},

		// --- swift-html-entities String.htmlEscape() ---
		// Kitura/swift-html-entities adds `htmlEscape()` as an extension on
		// String. It encodes <, >, &, ", ' (and optionally non-ASCII) into HTML5
		// entity references, making the output safe for HTML body or attribute
		// contexts. The method takes no positional args; the receiver string is
		// the value being neutralized.
		{
			ID:          "swift.htmlentities.htmlescape",
			Language:    rules.LangSwift,
			Pattern:     `\.htmlEscape\s*\(`,
			ObjectType:  "",
			MethodName:  "htmlEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "swift-html-entities String.htmlEscape() encodes <, >, &, \", ' as HTML5 entity references, neutralizing XSS in HTML output",
		},

		// =====================================================================
		// Cryptographic primitives (CWE-330, CWE-347) — proper key derivation
		// and signature verification from Apple swift-crypto / CryptoKit.
		// =====================================================================

		// --- swift-crypto / CryptoKit HKDF<H>.deriveKey(...) ---
		// `HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)`
		// is the IETF RFC 5869 HKDF function. Feeding low-entropy input through
		// HKDF with a non-empty salt produces a cryptographically strong key
		// suitable for symmetric encryption. The result is a SymmetricKey, not
		// the original input — taint on the IKM does not propagate to the key.
		{
			ID:          "swift.crypto.hkdf.derivekey",
			Language:    rules.LangSwift,
			Pattern:     `HKDF(?:<[^>]+>)?\.deriveKey\s*\(`,
			ObjectType:  "HKDF",
			MethodName:  "deriveKey",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto},
			Description: "swift-crypto/CryptoKit HKDF.deriveKey performs RFC 5869 HMAC-based key derivation, producing a fresh SymmetricKey from input key material",
		},

		// --- CryptoKit Curve25519/P256/P384/P521 PublicKey.isValidSignature ---
		// `publicKey.isValidSignature(signature, for: data)` performs full
		// cryptographic signature verification on the supplied data. A flow
		// where the data has been authenticated by isValidSignature == true is
		// no longer a signature-bypass risk for downstream deserialization or
		// crypto-decision sinks. Method name is unique to CryptoKit/swift-crypto
		// signing types so no receiver constraint is needed.
		{
			ID:          "swift.cryptokit.publickey.isvalidsignature",
			Language:    rules.LangSwift,
			Pattern:     `\.isValidSignature\s*\(`,
			ObjectType:  "",
			MethodName:  "isValidSignature",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkDeserialize},
			Description: "CryptoKit/swift-crypto PublicKey.isValidSignature(_:for:) verifies an Ed25519/ECDSA signature over the supplied data, authenticating it before further processing",
		},

		// =====================================================================
		// AEAD authenticated decryption (CWE-345 / CWE-502 sanitizer)
		// =====================================================================
		// Authenticated-encryption-with-associated-data (AEAD) `open(_:using:)`
		// methods cryptographically verify the integrity and origin of the
		// ciphertext+nonce+tag bundle before returning plaintext. A successful
		// return from these calls is proof that the data was produced by a
		// holder of the symmetric key — so the resulting plaintext is no
		// longer a CWE-345 (insufficient verification of data authenticity)
		// or CWE-502 (untrusted-data deserialization) risk for downstream
		// deserializers / trust-boundary sinks.
		//
		// These sanitizers do NOT neutralise injection categories (SQL,
		// Command, XSS, Path) — authenticity ≠ syntactic safety.

		// --- CryptoKit AES-GCM ---
		// `try AES.GCM.open(sealedBox, using: key)` decrypts an AES-GCM
		// AEAD-sealed payload and throws on tag mismatch.
		// Receiver text "AES.GCM" matches ObjectType "GCM" via the
		// qualified-receiver heuristic in matcher.go (recvLast "gcm" ==
		// lastPart "gcm").
		{
			ID:          "swift.cryptokit.aesgcm.open",
			Language:    rules.LangSwift,
			Pattern:     `AES\.GCM\.open\s*\(`,
			ObjectType:  "GCM",
			MethodName:  "open",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "CryptoKit AES.GCM.open(_:using:) performs AEAD decryption — successful return cryptographically authenticates the ciphertext, nonce and tag against the supplied SymmetricKey, so the resulting plaintext is integrity-checked and no longer an unauthenticated-data risk for downstream deserialization or trust-boundary sinks",
		},

		// --- CryptoKit ChaCha20-Poly1305 ---
		// `try ChaChaPoly.open(sealedBox, using: key)` decrypts a ChaCha20-
		// Poly1305 AEAD-sealed payload. Same authenticity guarantee as
		// AES-GCM.
		{
			ID:          "swift.cryptokit.chachapoly.open",
			Language:    rules.LangSwift,
			Pattern:     `ChaChaPoly\.open\s*\(`,
			ObjectType:  "ChaChaPoly",
			MethodName:  "open",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "CryptoKit ChaChaPoly.open(_:using:) performs AEAD decryption with ChaCha20-Poly1305 — successful return cryptographically authenticates the ciphertext, nonce and tag against the supplied SymmetricKey, so the resulting plaintext is integrity-checked and no longer an unauthenticated-data risk for downstream deserialization or trust-boundary sinks",
		},

		// =====================================================================
		// swift-sodium (jedisct1/swift-sodium) — libsodium AEAD + signature
		// authenticated decryption sanitizers (CWE-345 / CWE-347 / CWE-502)
		// =====================================================================
		// All entries follow the return-value sanitizer model: each method
		// returns Bytes? where nil indicates MAC/signature failure, so a
		// non-nil return is cryptographically authenticated against a key the
		// caller already trusts. Only SnkDeserialize and SnkTrustBoundary are
		// neutralized — AEAD/signature schemes authenticate origin but do NOT
		// make plaintext syntactically safe (no SQL/Command/HTML neutrality).

		// --- swift-sodium SecretBox.open (XSalsa20-Poly1305 secret-key AEAD) ---
		// `sodium.secretBox.open(authenticatedCipherText:secretKey:)` and the
		// nonceAndAuthenticatedCipherText / explicit-nonce variants all return
		// Bytes? — non-nil only when the Poly1305 MAC verifies against the
		// SecretBox.Key. Receiver text "sodium.secretBox" matches ObjectType
		// "SecretBox" via the qualified-receiver heuristic in matcher.go
		// (recvLast "secretbox" == lastPart "secretbox").
		{
			ID:          "swift.sodium.secretbox.open",
			Language:    rules.LangSwift,
			Pattern:     `\.secretBox\.open\s*\(`,
			ObjectType:  "SecretBox",
			MethodName:  "open",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "swift-sodium SecretBox.open(authenticatedCipherText:secretKey:) — XSalsa20-Poly1305 secret-key AEAD authenticated decryption returns plaintext only when the Poly1305 MAC validates against the supplied secret key, integrity-checking the ciphertext for downstream deserialization or trust-boundary sinks",
		},

		// --- swift-sodium Box.open (Curve25519 + XSalsa20-Poly1305 public-key AEAD) ---
		// `sodium.box.open(authenticatedCipherText:senderPublicKey:recipientSecretKey:)`
		// (and nonceAndAuthenticatedCipherText / anonymousCipherText variants)
		// returns Bytes? — non-nil only when the Poly1305 MAC verifies against
		// the recipient's secret key + sender's public key (X25519 ECDH).
		// Receiver "sodium.box" → ObjectType "Box" via recvLast "box".
		{
			ID:          "swift.sodium.box.open",
			Language:    rules.LangSwift,
			Pattern:     `\.box\.open\s*\(\s*(?:authenticatedCipherText|nonceAndAuthenticatedCipherText|anonymousCipherText)\s*:`,
			ObjectType:  "Box",
			MethodName:  "open",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "swift-sodium Box.open(authenticatedCipherText:senderPublicKey:recipientSecretKey:) — Curve25519 + XSalsa20-Poly1305 public-key AEAD returns plaintext only when the Poly1305 MAC verifies against the X25519-derived shared secret, authenticating the sender for downstream deserialization or trust-boundary sinks",
		},

		// --- swift-sodium Aead.XChaCha20Poly1305Ietf.decrypt (XChaCha20-Poly1305 IETF) ---
		// `sodium.aead.xchacha20poly1305ietf.decrypt(authenticatedCipherText:secretKey:additionalData:)`
		// returns Bytes? — non-nil only when the Poly1305 MAC verifies against
		// the SecretKey + 24-byte XChaCha20 nonce + optional AAD. Receiver
		// "sodium.aead.xchacha20poly1305ietf" → ObjectType
		// "XChaCha20Poly1305Ietf" via recvLast match.
		{
			ID:          "swift.sodium.aead.xchacha20poly1305ietf.decrypt",
			Language:    rules.LangSwift,
			Pattern:     `\.xchacha20poly1305ietf\.decrypt\s*\(`,
			ObjectType:  "XChaCha20Poly1305Ietf",
			MethodName:  "decrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "swift-sodium Aead.XChaCha20Poly1305Ietf.decrypt(authenticatedCipherText:secretKey:additionalData:) — XChaCha20-Poly1305-IETF AEAD authenticated decryption returns plaintext only when the Poly1305 MAC validates against the secret key, 24-byte nonce, and optional additional data, integrity-checking the ciphertext for downstream deserialization or trust-boundary sinks",
		},

		// --- swift-sodium Aead.ChaCha20Poly1305Ietf.decrypt (ChaCha20-Poly1305 IETF) ---
		// Same authenticity guarantee as the XChaCha20 variant but with the
		// shorter 12-byte ChaCha20 nonce defined in RFC 7539.
		{
			ID:          "swift.sodium.aead.chacha20poly1305ietf.decrypt",
			Language:    rules.LangSwift,
			Pattern:     `\.chacha20poly1305ietf\.decrypt\s*\(`,
			ObjectType:  "ChaCha20Poly1305Ietf",
			MethodName:  "decrypt",
			Neutralizes: []taint.SinkCategory{taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "swift-sodium Aead.ChaCha20Poly1305Ietf.decrypt(authenticatedCipherText:secretKey:additionalData:) — RFC 7539 ChaCha20-Poly1305 AEAD authenticated decryption returns plaintext only when the Poly1305 MAC validates against the secret key, 12-byte nonce, and optional additional data, integrity-checking the ciphertext for downstream deserialization or trust-boundary sinks",
		},

		// --- swift-sodium Sign.open (Ed25519 signed-message verification) ---
		// `sodium.sign.open(signedMessage:publicKey:)` returns Bytes? — non-nil
		// only when the Ed25519 signature attached to the message validates
		// against the supplied PublicKey. Successful return authenticates the
		// message origin so it is no longer a CWE-347 signature-bypass risk.
		// Receiver "sodium.sign" → ObjectType "Sign" via recvLast match.
		{
			ID:          "swift.sodium.sign.open",
			Language:    rules.LangSwift,
			Pattern:     `\.sign\.open\s*\(\s*signedMessage\s*:`,
			ObjectType:  "Sign",
			MethodName:  "open",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "swift-sodium Sign.open(signedMessage:publicKey:) verifies an Ed25519 signature on a signed message and returns the original plaintext only when the signature validates against the public key — authenticated origin neutralizes CWE-347 signature-bypass and unauthenticated-data risks for downstream deserialization or trust-boundary sinks",
		},

		// =====================================================================
		// JOSE/JWS signature validation (CWE-347 sanitizer)
		// =====================================================================

		// --- JOSESwift (airsidemobile) JWS.validate(with:) ---
		// `try jws.validate(with: publicKey)` performs full cryptographic
		// signature verification on a parsed JWS object and throws
		// SwiftJOSEError.signatureInvalid on mismatch. A flow where the JWS
		// has been validated against a real public key is authenticated and
		// no longer a CWE-347 signature-bypass risk for downstream consumers
		// of the payload (deserialization, authz decisions).
		// Receiver "jws" matches ObjectType "JWS" via direct lastPart match.
		{
			ID:          "swift.joseswift.jws.validate",
			Language:    rules.LangSwift,
			Pattern:     `\.validate\s*\(\s*with\s*:`,
			ObjectType:  "JWS",
			MethodName:  "validate",
			Neutralizes: []taint.SinkCategory{taint.SnkCrypto, taint.SnkDeserialize, taint.SnkTrustBoundary},
			Description: "JOSESwift JWS.validate(with: publicKey) verifies the JWS signature against the supplied public key (throwing SwiftJOSEError.signatureInvalid on mismatch) — successful validation authenticates the payload so it is no longer a CWE-347 signature-bypass or unauthenticated-data risk",
		},

		// =====================================================================
		// Foundation temporal-parse sanitizers (type-coerce string → typed value)
		// =====================================================================
		// Each entry takes the user-controlled string at args[0] (the `from:`
		// label) and returns a strongly-typed Foundation value (Date / NSNumber).
		// On parse failure the result is nil and no string bytes survive into
		// the return value, so the typed result can no longer carry an
		// injection payload for downstream string-context sinks (SQL, command,
		// log, filesystem, HTML output, redirect). Mirrors the cross-language
		// temporal-parse wave: Kotlin PR #600, Rust PR #688, JS PR #691, Ruby
		// PR #692, PHP PR #695, C# PR #697, Groovy PR #700, Perl PR #701.

		// --- Foundation DateFormatter.date(from:) ---------------------------
		// `dateFormatter.date(from: userInput)` parses against the formatter's
		// dateFormat / locale and returns Date? — the result is a 64-bit
		// TimeInterval, not the original string. Receiver "dateFormatter"
		// matches ObjectType "DateFormatter" via the matcher's direct-equality
		// path; receiver "d" matches via the prefix-abbreviation heuristic.
		{
			ID:          "swift.dateformatter.datefromstring",
			Language:    rules.LangSwift,
			Pattern:     `\.date\s*\(\s*from\s*:`,
			ObjectType:  "DateFormatter",
			MethodName:  "date",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Foundation DateFormatter.date(from:) parses the input string against the configured dateFormat and returns Date? (nil on parse failure) — the typed Date no longer carries the original string bytes and cannot be coerced back into an injection payload for downstream string-context sinks",
		},

		// --- Foundation ISO8601DateFormatter.date(from:) --------------------
		// `iso.date(from: userInput)` parses strictly against RFC 3339 / ISO
		// 8601 and returns Date? — invalid input produces nil. Receiver "iso"
		// matches ObjectType "ISO8601DateFormatter" via the prefix-abbreviation
		// heuristic (HasPrefix("iso8601dateformatter", "iso")). Idiomatic
		// usage is `let iso = ISO8601DateFormatter()`; other receivers like
		// "isoFormatter" do not match (not a prefix of the lowercased type).
		{
			ID:          "swift.iso8601dateformatter.datefromstring",
			Language:    rules.LangSwift,
			Pattern:     `\.date\s*\(\s*from\s*:`,
			ObjectType:  "ISO8601DateFormatter",
			MethodName:  "date",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Foundation ISO8601DateFormatter.date(from:) parses strictly against RFC 3339 / ISO 8601 and returns Date? (nil on parse failure) — the typed Date no longer carries the original string bytes and cannot be coerced back into an injection payload",
		},

		// --- Foundation NumberFormatter.number(from:) -----------------------
		// `numberFormatter.number(from: userInput)` parses the string under
		// the formatter's locale/numberStyle and returns NSNumber? (nil on
		// parse failure). The NSNumber wraps an Int64/Double — interpolating
		// it produces a controlled numeric string, not the original input.
		// Receiver "numberFormatter" matches via direct equality.
		{
			ID:          "swift.numberformatter.numberfromstring",
			Language:    rules.LangSwift,
			Pattern:     `\.number\s*\(\s*from\s*:`,
			ObjectType:  "NumberFormatter",
			MethodName:  "number",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkLog, taint.SnkFileWrite, taint.SnkFileRead, taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Foundation NumberFormatter.number(from:) parses the input under the formatter's locale/numberStyle and returns NSNumber? (nil on parse failure) — the wrapped numeric value cannot be coerced back into an injection payload for downstream string-context sinks",
		},

		// --- NoSQL: MongoSwift / MongoKitten BSON document constructors ---
		{
			ID:          "swift.mongoswift.document_init",
			Language:    rules.LangSwift,
			Pattern:     `BSONDocument\s*\(`,
			ObjectType:  "BSONDocument",
			MethodName:  "BSONDocument.init",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoSwift BSONDocument constructor binds values as typed BSON entries (no string interpolation into the query)",
		},
		{
			ID:          "swift.mongokitten.document_init",
			Language:    rules.LangSwift,
			Pattern:     `MongoKitten\.Document\s*\(`,
			ObjectType:  "MongoKitten.Document",
			MethodName:  "Document.init",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoKitten Document constructor builds a typed BSON document (values bound as data, not concatenated)",
		},
		{
			ID:          "swift.bson.objectid_init",
			Language:    rules.LangSwift,
			Pattern:     `\bBSONObjectID\s*\(`,
			ObjectType:  "BSONObjectID",
			MethodName:  "BSONObjectID.init",
			Neutralizes: []taint.SinkCategory{taint.SnkNoSQL},
			Description: "MongoSwift BSONObjectID throwing init validates the 24-char hex string and returns a typed ObjectID (rejects malformed input)",
		},

		// --- Header injection (CWE-93 CRLF) — strip + typed-container ---
		{
			ID:          "swift.header.strip_crlf",
			Language:    rules.LangSwift,
			Pattern:     `\.replacingOccurrences\s*\(\s*of\s*:\s*"\\\\r"|\.components\s*\(\s*separatedBy\s*:\s*\.newlines\s*\)`,
			ObjectType:  "String",
			MethodName:  "String.replacingOccurrences/components(newlines)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader, taint.SnkLog},
			Description: "Manual CR/LF stripping (replacingOccurrences / components(separatedBy: .newlines)) — defends header / log injection (CWE-93)",
		},
		{
			ID:          "swift.urlsession.urlrequest_typed",
			Language:    rules.LangSwift,
			Pattern:     `URLRequest\s*\([^)]+\)|\.addValue\s*\(\s*[^,]+\s*,\s*forHTTPHeaderField\s*:`,
			ObjectType:  "URLRequest",
			MethodName:  "URLRequest.addValue(forHTTPHeaderField:)",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Foundation URLRequest.addValue(_:forHTTPHeaderField:) — typed header setter; Foundation rejects header values containing CR/LF and validates token RFC compliance",
		},
		{
			ID:          "swift.alamofire.httpheaders_typed",
			Language:    rules.LangSwift,
			Pattern:     `HTTPHeaders\s*\(\s*\[|HTTPHeader\s*\(\s*name\s*:`,
			ObjectType:  "Alamofire.HTTPHeaders",
			MethodName:  "Alamofire.HTTPHeaders",
			Neutralizes: []taint.SinkCategory{taint.SnkHeader},
			Description: "Alamofire HTTPHeaders / HTTPHeader typed container — typed multi-header container; rejects CR/LF (delegates to URLRequest validation)",
		},

		// --- Eval sanitizers ---
		{
			ID:          "swift.jsonserialization.parse",
			Language:    rules.LangSwift,
			Pattern:     `JSONSerialization\.jsonObject\s*\(\s*with\s*:|JSONDecoder\s*\(\s*\)\.decode\s*\(`,
			ObjectType:  "JSONSerialization/JSONDecoder",
			MethodName:  "jsonObject/JSONDecoder.decode",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Foundation JSONSerialization.jsonObject / JSONDecoder.decode — strict JSON parser into typed Codable value (no script execution); safe alternative to ad-hoc eval on JSON inputs",
		},
		{
			ID:          "swift.nsexpression_evaluator",
			Language:    rules.LangSwift,
			Pattern:     `NSExpression\s*\(\s*format\s*:`,
			ObjectType:  "NSExpression",
			MethodName:  "NSExpression(format:)",
			Neutralizes: []taint.SinkCategory{taint.SnkEval},
			Description: "Foundation NSExpression(format:) — restricted expression evaluator (key-path / arithmetic / aggregate functions only, no arbitrary code); safe replacement for NSPredicate/NSExpression eval patterns on validated input",
		},

		// =====================================================================
		// Unrestricted file upload (CWE-434) — type / extension allowlist gates
		// for the SnkUpload sinks (swift.vapor.fileio.writefile,
		// swift.vapor.file.filename, swift.vapor.request.body.collect). Until now
		// no Swift sanitizer neutralized SnkUpload, so every tainted upload flow
		// reaching those sinks fired unconditionally. Mirrors the cross-language
		// upload-guard wave: Java Tika.detect (java_sanitizers), JS file-type /
		// mime lookup (javascript_sanitizers), Lua validate_extension / allowlist.
		// =====================================================================

		// --- UTType content/extension type detection (allowlist gate) ---
		// UniformTypeIdentifiers' `UTType(filenameExtension:)` / `UTType(mimeType:)`
		// resolve a client-supplied extension or MIME string into a typed UTType,
		// which is then checked against an allowlist (e.g. `[.jpeg, .png].contains(t)`).
		// Routing the upload's extension/MIME through this typed resolver before
		// storing it neutralizes the unrestricted-upload risk (CWE-434).
		{
			ID:          "swift.uttype.typecheck",
			Language:    rules.LangSwift,
			Pattern:     `\bUTType\s*\(\s*(?:filenameExtension|mimeType)\s*:`,
			ObjectType:  "UTType",
			MethodName:  "UTType(filenameExtension:)/UTType(mimeType:)",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "UniformTypeIdentifiers UTType(filenameExtension:) / UTType(mimeType:) resolves a client-supplied extension/MIME into a typed UTType for an allowlist check, gating which file types may be stored (CWE-434 prevention when paired with an allowlist)",
		},
		// --- Extension/MIME allowlist .contains() gate ---
		// The idiomatic Swift upload guard is `guard allowedExtensions.contains(
		// url.pathExtension) else { throw Abort(.unsupportedMediaType) }`. A
		// dedicated allowlist set name (allowedExtensions / allowedTypes /
		// permittedExtensions / allowedMimeTypes) used with .contains() restricts
		// the upload to permitted file types before it is persisted. The specific
		// set names avoid matching unrelated `someList.contains(x)` calls.
		{
			ID:          "swift.upload.extension.allowlist",
			Language:    rules.LangSwift,
			Pattern:     `(?:allowedExtensions|allowedTypes|permittedExtensions|allowedMimeTypes)\.contains\s*\(`,
			ObjectType:  "",
			MethodName:  "allowedExtensions.contains/allowedTypes.contains",
			Neutralizes: []taint.SinkCategory{taint.SnkUpload},
			Description: "Extension/MIME allowlist membership check (allowedExtensions/allowedTypes/permittedExtensions/allowedMimeTypes .contains(ext)) gates an upload so only permitted file types are stored (CWE-434 prevention)",
		},

		// =====================================================================
		// CSV / spreadsheet-formula injection (CWE-1236) — formula-escape helpers
		// for the SnkCSV sinks (swift.codablecsv.writer.write, swift.swiftcsv.append).
		// Previously no Swift sanitizer neutralized SnkCSV. Mirrors the
		// cross-language CSV-escape wave: Python defusedcsv, JS escapeCsvFormula /
		// csv-stringify { quoted: true }, Lua csv_escape / leading-quote prefix.
		// =====================================================================

		// --- Named CSV-formula escape helper ---
		// A custom helper (escapeCSVFormula / sanitizeCSVCell / escapeFormula /
		// csvEscape / …) that prefixes a single quote (or otherwise neutralizes a
		// cell beginning with =, +, -, @, TAB, or CR) before it is written to a
		// spreadsheet-bound CSV. \b anchors the name so unrelated helpers like
		// escapeHTML(…) do not match.
		{
			ID:          "swift.csv.formula_escape_helper",
			Language:    rules.LangSwift,
			Pattern:     `\b(?:escapeCSVFormula|sanitizeCSVCell|sanitizeCSVField|escapeFormula|csvEscape|escapeCSVCell)\s*\(`,
			ObjectType:  "",
			MethodName:  "escapeCSVFormula/sanitizeCSVCell/escapeFormula/csvEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "CSV/formula-injection escape helper — neutralizes cells beginning with =, +, -, @, TAB, or CR (typically by prefixing a single quote) before they are written to a spreadsheet-bound CSV (CWE-1236)",
		},
		// --- Inline leading single-quote prefix ---
		// The minimal manual mitigation: prepend a literal single quote to a cell
		// value (`"'" + value`) so a spreadsheet treats the cell as text rather
		// than evaluating it as a formula. Matches the Swift string-concat idiom
		// `"'" + …` / `"'" + value`.
		{
			ID:          "swift.csv.leading_quote_prefix",
			Language:    rules.LangSwift,
			Pattern:     `"'"\s*\+\s*\w`,
			ObjectType:  "",
			MethodName:  "leading single-quote prefix",
			Neutralizes: []taint.SinkCategory{taint.SnkCSV},
			Description: "Inline CSV-formula-injection mitigation prefixing a literal single quote to a cell value (\"'\" + value) so a spreadsheet treats the cell as text, not a formula (CWE-1236)",
		},
	}
}
