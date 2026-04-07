package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
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
			Pattern:     `\.private\b|\.sensitive\b|OSLogPrivacy\.private|OSLogPrivacy\.sensitive`,
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
			Pattern:     `RequestInterceptor|RequestAdapter|\.adapt\s*\(\s*.*urlRequest`,
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
			ID:          "swift.xpath.escaping",
			Language:    rules.LangSwift,
			Pattern:     `\.replacingOccurrences\(of:\s*"'".*"&apos;"`,
			ObjectType:  "String",
			MethodName:  "XPath string escaping",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XPath value escaping prevents injection via single-quote replacement",
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
	}
}
