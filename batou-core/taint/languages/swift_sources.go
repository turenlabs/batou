package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (c *SwiftCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- URLSession / URLRequest ---
		{
			ID:          "swift.urlsession.datatask",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `URLSession\.shared\.dataTask|URLSession\(.*\)\.dataTask|\.dataTask\(\s*with:`,
			ObjectType:  "URLSession",
			MethodName:  "dataTask",
			Description: "URLSession network response data",
			Assigns:     "return",
		},
		{
			ID:          "swift.urlrequest",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `URLRequest\(\s*url:`,
			ObjectType:  "URLRequest",
			MethodName:  "init",
			Description: "URL request construction",
			Assigns:     "return",
		},

		// --- UserDefaults ---
		{
			ID:          "swift.userdefaults.read",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `UserDefaults\.standard\.(?:string|object|data|integer|bool|float|double|array|dictionary)\(\s*forKey:`,
			ObjectType:  "UserDefaults",
			MethodName:  "string/object/data(forKey:)",
			Description: "UserDefaults stored value (potentially tampered)",
			Assigns:     "return",
		},

		// --- Environment / CLI ---
		{
			ID:          "swift.processinfo.environment",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangSwift,
			Pattern:     `ProcessInfo\.processInfo\.environment`,
			ObjectType:  "ProcessInfo",
			MethodName:  "environment",
			Description: "Process environment variables",
			Assigns:     "return",
		},
		{
			ID:          "swift.commandline.arguments",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangSwift,
			Pattern:     `CommandLine\.arguments`,
			ObjectType:  "CommandLine",
			MethodName:  "arguments",
			Description: "Command-line arguments",
			Assigns:     "return",
		},
		// POSIX getenv() bridged from Glibc/Darwin — the canonical low-level
		// environment read in server-side Swift (and any C-interop code). Returns
		// a UnsafePointer<CChar>? that is typically wrapped via String(cString:).
		// Anchored with \b so it does not substring-match identifiers like
		// `myGetenv(` or `forgetenv(`.
		{
			ID:          "swift.posix.getenv",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangSwift,
			Pattern:     `\bgetenv\s*\(`,
			ObjectType:  "",
			MethodName:  "getenv",
			Description: "POSIX getenv() environment variable read (C interop) — attacker-influenced process environment",
			Assigns:     "return",
		},
		// ProcessInfo.processInfo.arguments — the Foundation accessor for the
		// process argument vector (alternative to the top-level CommandLine.arguments).
		{
			ID:          "swift.processinfo.arguments",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangSwift,
			Pattern:     `ProcessInfo\.processInfo\.arguments`,
			ObjectType:  "ProcessInfo",
			MethodName:  "arguments",
			Description: "ProcessInfo.processInfo.arguments — process argument vector (command-line input)",
			Assigns:     "return",
		},

		// --- Pasteboard ---
		{
			ID:          "swift.pasteboard.read",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `UIPasteboard\.general\.(?:string|strings|image|images|url|urls|data|items)`,
			ObjectType:  "UIPasteboard",
			MethodName:  "string/data",
			Description: "Pasteboard data from user clipboard",
			Assigns:     "return",
		},

		// --- UI Text Input ---
		{
			ID:          "swift.uitextfield.text",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `(?:[tT]extField|input|[fF]ield)\.text\b`,
			ObjectType:  "UITextField",
			MethodName:  "text",
			Description: "Text field user input",
			Assigns:     "return",
		},
		{
			ID:          "swift.uitextview.text",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `textView\.text|UITextView[^;]*\.text`,
			ObjectType:  "UITextView",
			MethodName:  "text",
			Description: "Text view user input",
			Assigns:     "return",
		},

		// --- WKWebView navigation ---
		{
			ID:          "swift.wkwebview.navigation",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `navigationAction\.request\.url|decisionHandler|webView\(.*decidePolicyFor`,
			ObjectType:  "WKWebView",
			MethodName:  "decidePolicyFor",
			Description: "WKWebView navigation request URL",
			Assigns:     "return",
		},

		// --- URL query parameters ---
		{
			ID:          "swift.url.queryitems",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `URLComponents\(.*\)\.queryItems|\.queryItems|\.value\(forQueryItem`,
			ObjectType:  "URLComponents",
			MethodName:  "queryItems",
			Description: "URL query parameters",
			Assigns:     "return",
		},

		// --- HTTP Cookies ---
		{
			ID:          "swift.httpcookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `HTTPCookieStorage\.shared\.cookies|HTTPCookie\.cookies\(`,
			ObjectType:  "HTTPCookieStorage",
			MethodName:  "cookies",
			Description: "HTTP cookie values",
			Assigns:     "return",
		},

		// NOTE: Bundle.main.path/url(forResource:) is intentionally NOT a taint
		// source. Bundle resources are files the developer SHIPS inside the app
		// bundle — they are app-controlled, not attacker-controlled, and the
		// lookup is constrained to the bundle (no traversal outside it). Modeling
		// them as a SrcFileRead source produced false positives whenever a bundled
		// fixture/asset path flowed into a file-read/network sink (e.g.
		// `Data(contentsOf: Bundle.main.url(forResource:))` in tests), without any
		// real attacker-controlled flow. Genuine user-input sources (request
		// params, query strings, env, stdin) are modeled elsewhere.

		// --- Deserialization ---
		{
			ID:          "swift.jsondecoder",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangSwift,
			Pattern:     `JSONDecoder\(\)\.decode\(|JSONSerialization\.jsonObject\(`,
			ObjectType:  "JSONDecoder",
			MethodName:  "decode",
			Description: "JSON deserialized data from untrusted source",
			Assigns:     "return",
		},

		// --- Deep link / URL scheme ---
		{
			ID:          "swift.deeplink.url",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `func\s+application\(.*open\s+url:\s*URL|func\s+scene\(.*openURLContexts`,
			ObjectType:  "UIApplicationDelegate",
			MethodName:  "application(_:open:)",
			Description: "Deep link / URL scheme input",
			Assigns:     "return",
		},

		// --- Vapor framework ---
		{
			ID:          "swift.vapor.req.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.query\[|req\.query\.decode\s*\(`,
			ObjectType:  "Request",
			MethodName:  "req.query",
			Description: "Vapor request query parameters",
			Assigns:     "return",
		},
		{
			ID:          "swift.vapor.req.content",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.content\.decode\s*\(|req\.content\[`,
			ObjectType:  "Request",
			MethodName:  "req.content",
			Description: "Vapor request body content",
			Assigns:     "return",
		},
		{
			ID:          "swift.vapor.req.parameters",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.parameters\.get\s*\(`,
			ObjectType:  "Request",
			MethodName:  "req.parameters.get",
			Description: "Vapor route parameters",
			Assigns:     "return",
		},
		{
			ID:          "swift.vapor.req.headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.headers\[|req\.headers\.first\(`,
			ObjectType:  "Request",
			MethodName:  "req.headers",
			Description: "Vapor request headers",
			Assigns:     "return",
		},
		{
			ID:          "swift.vapor.req.cookies",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.cookies\[|req\.cookies\.all`,
			ObjectType:  "Request",
			MethodName:  "req.cookies",
			Description: "Vapor request cookies",
			Assigns:     "return",
		},

		// --- Vapor request body ---
		{
			ID:          "swift.vapor.req.body.string",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.body\.string|request\.body\.string`,
			ObjectType:  "Request",
			MethodName:  "req.body.string",
			Description: "Vapor request body as raw string",
			Assigns:     "return",
		},
		{
			ID:          "swift.vapor.req.body.data",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.body\.data|request\.body\.data`,
			ObjectType:  "Request",
			MethodName:  "req.body.data",
			Description: "Vapor request body as raw Data",
			Assigns:     "return",
		},

		// --- SwiftNIO ---
		{
			ID:          "swift.nio.channel.read",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `channelRead\s*\(\s*context:|func\s+channelRead\(`,
			ObjectType:  "ChannelInboundHandler",
			MethodName:  "channelRead",
			Description: "SwiftNIO channel inbound data",
			Assigns:     "return",
		},

		// NOTE: String(contentsOfFile:) / Data(contentsOf:) are intentionally NOT
		// taint SOURCES. They ARE sinks (a tainted PATH flowing into them is
		// path-traversal / SSRF — see swift_sinks.go), but modeling their RESULT
		// (the file's content) as untrusted produced false positives: ordinary
		// reads of app-bundled or constant-path files flowed into benign sinks
		// (e.g. `print(Data(contentsOf: bundleURL))` flagged as log injection).
		// File-content-as-source is a niche second-order pattern not worth the FP
		// rate; genuine user input (request params, query strings) is the source.
		// These entries were latent before (the arg-label matcher fix activated
		// them), so removing them is FP-only — no real recall is lost.

		// --- PropertyList deserialization ---
		{
			ID:          "swift.plistdecoder",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangSwift,
			Pattern:     `PropertyListDecoder\(\)\.decode\(|PropertyListSerialization\.propertyList\(`,
			ObjectType:  "PropertyListDecoder",
			MethodName:  "decode",
			Description: "Property list deserialized data",
			Assigns:     "return",
		},

		// --- NSXMLParser (external XML) ---
		{
			ID:          "swift.xmlparser",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `XMLParser\(\s*data:|XMLParser\(\s*contentsOf:`,
			ObjectType:  "XMLParser",
			MethodName:  "XMLParser(data:)",
			Description: "XML parser with potentially untrusted data",
			Assigns:     "return",
		},

		// --- ZIPFoundation archive readers (Zip Slip / Tar Slip — CWE-22) ---
		// Opening a ZIP archive from untrusted input (URL or Data) produces
		// entries whose `.path` property is attacker-controlled. When that
		// path flows into file-write operations (FileManager.createFile,
		// Data.write(to:), archive.extract(_:to:)) without normalization
		// via `.standardizedFileURL` or a prefix check, the archive can
		// escape its intended destination directory.
		//
		// Refs: Snyk "Zip Slip" disclosure (2018), CVE-2018-1000544 class.
		{
			ID:          "swift.zipfoundation.archive.url",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `Archive\s*\(\s*url:`,
			ObjectType:  "Archive",
			MethodName:  "Archive",
			Description: "ZIPFoundation Archive opened from URL — entries carry attacker-controlled paths",
			Assigns:     "return",
		},
		{
			ID:          "swift.zipfoundation.archive.data",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `Archive\s*\(\s*data:`,
			ObjectType:  "Archive",
			MethodName:  "Archive",
			Description: "ZIPFoundation Archive opened from Data — entries carry attacker-controlled paths",
			Assigns:     "return",
		},

		// --- Additional Swift sources ---
		{
			ID:          "swift.vapor.request.content",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.content|request\.content`,
			ObjectType:  "Vapor.Request",
			MethodName:  "content",
			Description: "Vapor request content (decoded body)",
			Assigns:     "return",
		},
		{
			ID:          "swift.urlsession.datatask.additional",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `URLSession\.shared\.dataTask|\.dataTask\s*\(`,
			ObjectType:  "URLSession",
			MethodName:  "dataTask",
			Description: "URLSession data task response (network data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.userdefaults.additional",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `UserDefaults\.standard\.string\s*\(|UserDefaults\.standard\.object\s*\(`,
			ObjectType:  "UserDefaults",
			MethodName:  "string/object",
			Description: "UserDefaults data (potentially tampered on jailbroken devices)",
			Assigns:     "return",
		},

		// --- Async URLSession (Swift concurrency) ---
		{
			ID:          "swift.urlsession.async.data",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `URLSession\.shared\.data\(\s*from:|URLSession\.shared\.data\(\s*for:`,
			ObjectType:  "URLSession",
			MethodName:  "data(from:)/data(for:)",
			Description: "URLSession async data fetch (Swift concurrency)",
			Assigns:     "return",
		},
		{
			ID:          "swift.urlsession.async.upload",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `URLSession\.shared\.upload\(\s*for:`,
			ObjectType:  "URLSession",
			MethodName:  "upload(for:)",
			Description: "URLSession async upload response data",
			Assigns:     "return",
		},
		{
			ID:          "swift.urlsession.async.download",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `URLSession\.shared\.download\(\s*from:|URLSession\.shared\.download\(\s*for:`,
			ObjectType:  "URLSession",
			MethodName:  "download(from:)",
			Description: "URLSession async download response",
			Assigns:     "return",
		},

		// --- Hummingbird framework ---
		{
			ID:          "swift.hummingbird.request.uri",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `request\.uri\.(?:path|queryString|string)|req\.uri\.(?:path|queryString|string)`,
			ObjectType:  "HBRequest",
			MethodName:  "request.uri",
			Description: "Hummingbird request URI components",
			Assigns:     "return",
		},
		{
			ID:          "swift.hummingbird.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `request\.body\.buffer|req\.body\.buffer`,
			ObjectType:  "HBRequest",
			MethodName:  "request.body.buffer",
			Description: "Hummingbird request body buffer",
			Assigns:     "return",
		},
		{
			ID:          "swift.hummingbird.request.headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `request\.headers\[|req\.headers\[`,
			ObjectType:  "HBRequest",
			MethodName:  "request.headers",
			Description: "Hummingbird request headers",
			Assigns:     "return",
		},
		{
			ID:          "swift.hummingbird.request.parameters",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `request\.parameters\.get\(|req\.parameters\.get\(`,
			ObjectType:  "HBRequest",
			MethodName:  "request.parameters.get",
			Description: "Hummingbird route parameters",
			Assigns:     "return",
		},

		// --- Vapor multipart ---
		{
			ID:          "swift.vapor.req.body.collect",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `req\.body\.collect\(|request\.body\.collect\(`,
			ObjectType:  "Request",
			MethodName:  "req.body.collect",
			Description: "Vapor request body collected as ByteBuffer",
			Assigns:     "return",
		},

		// --- SwiftUI @AppStorage ---
		{
			ID:          "swift.swiftui.appstorage",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `@AppStorage\(`,
			ObjectType:  "SwiftUI",
			MethodName:  "@AppStorage",
			Description: "SwiftUI @AppStorage wraps UserDefaults (tamper risk on jailbroken devices)",
			Assigns:     "return",
		},

		// --- Notification payload ---
		{
			ID:          "swift.notification.userinfo",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `notification\.userInfo|\.userInfo\s*\?\?\[`,
			ObjectType:  "Notification",
			MethodName:  "userInfo",
			Description: "Notification payload data (may contain cross-process data)",
			Assigns:     "return",
		},

		// --- Multipeer connectivity ---
		{
			ID:          "swift.multipeer.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `func\s+session\(.*didReceive\s+data:`,
			ObjectType:  "MCSessionDelegate",
			MethodName:  "session(_:didReceive:)",
			Description: "MultipeerConnectivity received data from peer",
			Assigns:     "return",
		},

		// --- Alamofire response data ---
		{
			ID:          "swift.alamofire.responsedata",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `\.responseData\s*\{|\.responseData\s*\(`,
			ObjectType:  "DataRequest",
			MethodName:  "responseData",
			Description: "Alamofire response data (network data from remote server)",
			Assigns:     "return",
		},
		{
			ID:          "swift.alamofire.responsestring",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `\.responseString\s*\{|\.responseString\s*\(`,
			ObjectType:  "DataRequest",
			MethodName:  "responseString",
			Description: "Alamofire response as string (network data from remote server)",
			Assigns:     "return",
		},
		{
			ID:          "swift.alamofire.responsedecodable",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `\.responseDecodable\s*\(`,
			ObjectType:  "DataRequest",
			MethodName:  "responseDecodable",
			Description: "Alamofire decoded response object (network data from remote server)",
			Assigns:     "return",
		},
		{
			ID:          "swift.alamofire.responsejson",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `\.responseJSON\s*\{|\.responseJSON\s*\(`,
			ObjectType:  "DataRequest",
			MethodName:  "responseJSON",
			Description: "Alamofire JSON response (network data from remote server)",
			Assigns:     "return",
		},

		// --- Moya response data ---
		{
			ID:          "swift.moya.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `\.response\s*\{\s*result\s+in|Moya\.Response`,
			ObjectType:  "MoyaProvider",
			MethodName:  "response",
			Description: "Moya network response data",
			Assigns:     "return",
		},

		// --- AsyncHTTPClient response ---
		{
			ID:          "swift.asynchttp.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `HTTPClient\.Response`,
			ObjectType:  "HTTPClient",
			MethodName:  "Response",
			Description: "AsyncHTTPClient response (network data)",
			Assigns:     "return",
		},

		// --- NSUserActivity Handoff (cross-device data) ---
		{
			ID:          "swift.nsuseractivity.userinfo",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `userActivity\.userInfo|activity\.userInfo`,
			ObjectType:  "NSUserActivity",
			MethodName:  "userActivity.userInfo",
			Description: "NSUserActivity Handoff payload from another device (trust boundary input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.nsuseractivity.webpageurl",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `userActivity\.webpageURL|activity\.webpageURL`,
			ObjectType:  "NSUserActivity",
			MethodName:  "userActivity.webpageURL",
			Description: "NSUserActivity universal link URL (trust boundary input)",
			Assigns:     "return",
		},

		// --- Shared Keychain read ---
		{
			ID:          "swift.keychain.shared.read",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `SecItemCopyMatching\s*\(`,
			ObjectType:  "Security",
			MethodName:  "SecItemCopyMatching",
			Description: "Keychain item read (may be from shared access group)",
			Assigns:     "return",
		},

		// --- App Group shared container ---
		{
			ID:          "swift.appgroup.userdefaults",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `UserDefaults\(\s*suiteName:`,
			ObjectType:  "UserDefaults",
			MethodName:  "UserDefaults(suiteName:)",
			Description: "App Group shared UserDefaults (data from extensions/other apps)",
			Assigns:     "return",
		},

		// --- iCloud ubiquity container (synced data from other devices) ---
		{
			ID:          "swift.filemanager.ubiquitycontainer",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `FileManager\.default\.url\(\s*forUbiquityContainerIdentifier:`,
			ObjectType:  "FileManager",
			MethodName:  "url(forUbiquityContainerIdentifier:)",
			Description: "iCloud ubiquity container URL (data synced from untrusted devices)",
			Assigns:     "return",
		},

		// --- Scene URL opening context (universal links / deep links) ---
		{
			ID:          "swift.scene.connectionoptions.urlcontexts",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `connectionOptions\.urlContexts|\.urlContexts\.first\.url`,
			ObjectType:  "UIScene",
			MethodName:  "connectionOptions.urlContexts",
			Description: "Scene URL opening contexts (universal links / deep link entry points)",
			Assigns:     "return",
		},

		// --- Database result sources (second-order injection) ---
		{
			ID:          "swift.coredata.fetch",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.fetch\s*\(\s*\w*[Ff]etch[RD]`,
			ObjectType:  "",
			MethodName:  "fetch",
			Description: "CoreData/SwiftData fetch request results (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.coredata.value.forkey",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.value\(\s*forKey:\s*"|\.primitiveValue\(\s*forKey:\s*"`,
			ObjectType:  "NSManagedObject",
			MethodName:  "value/primitiveValue",
			Description: "CoreData dynamic KVC property access (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.grdb.row.fetch",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `Row\.fetch(?:All|One|Cursor)\s*\(`,
			ObjectType:  "",
			MethodName:  "fetchAll/fetchOne/fetchCursor",
			Description: "GRDB row fetch results (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqlite3.column.text",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `sqlite3_column_text\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_text",
			Description: "SQLite3 C API text column retrieval (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqlite3.column.int",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `sqlite3_column_int(?:64)?\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_int/sqlite3_column_int64",
			Description: "SQLite3 C API integer column retrieval (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqlite3.column.double",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `sqlite3_column_double\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_double",
			Description: "SQLite3 C API double column retrieval (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqlite3.column.blob",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `sqlite3_column_blob\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_blob",
			Description: "SQLite3 C API blob column retrieval (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.fluent.query.on",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.query\s*\(\s*on:\s*`,
			ObjectType:  "",
			MethodName:  "query",
			Description: "Vapor Fluent ORM query builder results (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.fluent.find",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.find\s*\([^,]+,\s*on:\s*`,
			ObjectType:  "",
			MethodName:  "find",
			Description: "Vapor Fluent ORM model find by ID (database data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.realm.objects",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `realm\.objects\s*\(\s*\w+\.self\s*\)`,
			ObjectType:  "Realm",
			MethodName:  "objects",
			Description: "Realm database query results",
			Assigns:     "return",
		},

		// --- WebSocket message receive (CWE-20) ---
		{
			ID:          "swift.websocket.urlsession.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `(?:webSocketTask|wsTask|socketTask)\.receive\s*[\({]`,
			ObjectType:  "WebSocketTask",
			MethodName:  "receive",
			Description: "URLSessionWebSocketTask message receive (attacker-controlled data)",
			Assigns:     "return",
		},
		{
			ID:          "swift.starscream.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `didReceive\(\s*event:\s*WebSocketEvent|websocketDidReceiveMessage|websocketDidReceiveData`,
			ObjectType:  "Starscream",
			MethodName:  "didReceive",
			Description: "Starscream WebSocket delegate message receive",
			Assigns:     "return",
		},
		{
			ID:          "swift.vapor.websocket.receive",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `ws\.onText\s*\{|ws\.onBinary\s*\{|websocket\.onText\s*\{|websocket\.onBinary\s*\{`,
			ObjectType:  "WebSocket",
			MethodName:  "onText/onBinary",
			Description: "Vapor WebSocket text/binary message receive (attacker-controlled data)",
			Assigns:     "return",
		},

		// --- Redis cache read (second-order injection) ---
		{
			ID:          "swift.redistack.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.(?:get|hget|hmget|hgetall|lpop|rpop|lrange)\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "get/hget/lpop/rpop/lrange",
			Description: "RediStack cache data retrieval (potentially untrusted content)",
			Assigns:     "return",
		},

		// --- Additional RediStack read sources for second-order taint (CWE-89, CWE-78, CWE-79, CWE-502) ---
		// The existing swift.redistack.get covers a fixed lump of method names
		// (get/hget/hmget/hgetall/lpop/rpop/lrange) but does not match many
		// other idiomatic RediStack reads. Redis-backed caches, session stores,
		// and queues routinely persist attacker-controlled values; reading
		// them back without sanitization is a real second-order injection
		// path. Mirrors java.jedis.* (PR #641), python redis-py read sources
		// (PR #685), and the multi-language Redis-source addition cycle.
		{
			ID:          "swift.redistack.mget",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.mget\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "mget",
			Description: "RediStack mget(_:as:) — Redis MGET multi-key fetch (potentially attacker-controlled cached content, second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.hkeys",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.hkeys\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "hkeys",
			Description: "RediStack hkeys(in:) — Redis HKEYS hash field names (second-order injection via attacker-controlled field names)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.hvals",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.hvals\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "hvals",
			Description: "RediStack hvals(in:as:) — Redis HVALS hash field values (second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.smembers",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.smembers\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "smembers",
			Description: "RediStack smembers(of:as:) — Redis SMEMBERS set members (second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.srandmember",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.srandmember\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "srandmember",
			Description: "RediStack srandmember(from:max:as:) — Redis SRANDMEMBER random set member (second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.spop",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.spop\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "spop",
			Description: "RediStack spop(from:max:as:) — Redis SPOP popped set member (second-order injection / queue payload)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.zrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.zrange\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "zrange",
			Description: "RediStack zrange(from:firstIndex:lastIndex:as:) — Redis ZRANGE sorted-set range (second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.zrangebyscore",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.zrangebyscore\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "zrangebyscore",
			Description: "RediStack zrangebyscore(from:withMinimumScoreOf:withMaximumScoreOf:as:) — Redis ZRANGEBYSCORE range by score (second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "swift.redistack.lindex",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `(?:redis|redisConn|redisClient)\.lindex\s*\(`,
			ObjectType:  "RedisClient",
			MethodName:  "lindex",
			Description: "RediStack lindex(_:from:as:) — Redis LINDEX list element by index (second-order injection)",
			Assigns:     "return",
		},

		// --- Soto AWS storage/queue reads (second-order injection, CWE-89/CWE-78/CWE-79/CWE-502) ---
		// Soto (the de-facto AWS SDK for server-side Swift / Vapor) already has
		// PartiQL/SQL injection SINKS for DynamoDB.executeStatement, Athena,
		// RedshiftData and TimestreamQuery (swift.soto.* in swift_sinks.go), but
		// no SOURCES — so data an attacker writes to S3, DynamoDB or SQS on one
		// request and the app reads back on a later request did not propagate
		// taint into downstream SQL/command/eval sinks. These objects routinely
		// hold attacker-controlled content (uploaded S3 objects, user-written
		// DynamoDB items, queued SQS message bodies). Mirrors the multi-language
		// AWS second-order read-source additions: java.aws.* / java.dynamodb.*
		// (PR #1034), kotlin.aws.* (S3 getObject / SQS receiveMessage /
		// DynamoDB getItem/query/scan/batchGetItem), php Aws\DynamoDb (PR #1033),
		// ruby aws-sdk-dynamodb (PR #1032). ObjectType is the Soto service type
		// (S3 / DynamoDB / SQS); the matcher direct-matches the canonical Soto
		// receiver names (s3 / dynamoDB / sqs) — same convention the existing
		// swift.soto sinks rely on.
		{
			ID:          "swift.soto.s3.getobject",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `\bs3\.getObject\s*\(`,
			ObjectType:  "S3",
			MethodName:  "getObject",
			Description: "Soto SotoS3 S3.getObject(_:) — returns a GetObjectOutput whose body is the stored object's bytes. Objects uploaded by users (or written by an earlier request) are attacker-controlled; reading them back and routing the content into a SQL/command/template sink is second-order injection (CWE-89/CWE-78/CWE-79).",
			Assigns:     "return",
		},
		{
			ID:          "swift.soto.dynamodb.getitem",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `\bdynamo(?:DB|db|Db)\.getItem\s*\(`,
			ObjectType:  "DynamoDB",
			MethodName:  "getItem",
			Description: "Soto SotoDynamoDB DynamoDB.getItem(_:) — returns a GetItemOutput.item map of AttributeValues persisted on a prior write. User-written item attributes are attacker-controlled; using them in a later query/command without sanitization is second-order injection (CWE-89/CWE-943).",
			Assigns:     "return",
		},
		{
			ID:          "swift.soto.dynamodb.query",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `\bdynamo(?:DB|db|Db)\.query\s*\(`,
			ObjectType:  "DynamoDB",
			MethodName:  "query",
			Description: "Soto SotoDynamoDB DynamoDB.query(_:) — returns a QueryOutput.items array of attacker-controllable item attributes. Routing read-back values into a downstream SQL/command/eval sink is second-order injection (CWE-89/CWE-943).",
			Assigns:     "return",
		},
		{
			ID:          "swift.soto.dynamodb.scan",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `\bdynamo(?:DB|db|Db)\.scan\s*\(`,
			ObjectType:  "DynamoDB",
			MethodName:  "scan",
			Description: "Soto SotoDynamoDB DynamoDB.scan(_:) — returns a ScanOutput.items array of attacker-controllable item attributes from a full-table scan. Read-back values reaching a downstream sink are second-order injection (CWE-89/CWE-943).",
			Assigns:     "return",
		},
		{
			ID:          "swift.soto.dynamodb.batchgetitem",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `\bdynamo(?:DB|db|Db)\.batchGetItem\s*\(`,
			ObjectType:  "DynamoDB",
			MethodName:  "batchGetItem",
			Description: "Soto SotoDynamoDB DynamoDB.batchGetItem(_:) — returns a BatchGetItemOutput.responses map of attacker-controllable item attributes fetched in bulk. Read-back values reaching a downstream sink are second-order injection (CWE-89/CWE-943).",
			Assigns:     "return",
		},
		{
			ID:          "swift.soto.sqs.receivemessage",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `\bsqs\.receiveMessage\s*\(`,
			ObjectType:  "SQS",
			MethodName:  "receiveMessage",
			Description: "Soto SotoSQS SQS.receiveMessage(_:) — returns a ReceiveMessageOutput.messages array whose body fields are producer-supplied (often attacker-controlled across a trust boundary). Consuming a message body and routing it into a SQL/command/eval sink without validation is second-order injection (CWE-89/CWE-78/CWE-502).",
			Assigns:     "return",
		},

		// --- CloudKit record fetch (second-order injection) ---
		{
			ID:          "swift.cloudkit.fetch",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.records\(\s*matching:|\.fetch\(\s*withRecordID:|CKQueryOperation`,
			ObjectType:  "CKDatabase",
			MethodName:  "records(matching:)/fetch(withRecordID:)",
			Description: "CloudKit database record fetch (iCloud-synced data, potentially tampered)",
			Assigns:     "return",
		},

		// ── WKWebView JavaScript bridge (CWE-79/CWE-94) ────────────
		// Matches `message.body` where `message: WKScriptMessage` is the
		// delegate parameter in WKScriptMessageHandler.userContentController.
		{
			ID:          "swift.wkscriptmessage.body",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `WKScriptMessage[^;]*\.body|didReceive\s+message:\s*WKScriptMessage`,
			ObjectType:  "WKScriptMessage",
			MethodName:  "message.body",
			Description: "WKWebView JavaScript-to-native bridge message body (attacker-controlled web content)",
			Assigns:     "return",
		},

		// ── QR code / barcode scanning (CWE-20) ────────────────────
		// Matches `readable.stringValue` where `readable: AVMetadataMachineReadableCodeObject`.
		{
			ID:          "swift.avcapture.metadata.stringvalue",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `AVMetadataMachineReadableCodeObject[^;]*\.stringValue|AVMetadataObject[^;]*\.stringValue`,
			ObjectType:  "AVMetadataMachineReadableCodeObject",
			MethodName:  "readable.stringValue",
			Description: "QR code / barcode scanned string value (physically attacker-controlled input)",
			Assigns:     "return",
		},

		// ── Share extension input (CWE-20) ─────────────────────────
		// Matches `provider.loadItem(forTypeIdentifier:)` call.
		{
			ID:          "swift.nsitemprovider.loaditem",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `\.loadItem\s*\(\s*forTypeIdentifier:|\.loadObject\s*\(\s*ofClass:|\.loadDataRepresentation\s*\(`,
			ObjectType:  "NSItemProvider",
			MethodName:  "provider.loadItem/itemProvider.loadItem",
			Description: "Share extension NSItemProvider data (untrusted input from other apps)",
			Assigns:     "return",
		},

		// ── HTTP response headers (CWE-113/CWE-918) ────────────────
		// Matches `response.allHeaderFields[...]` and `response.value(forHTTPHeaderField:)`.
		// ObjectType "HTTPURLResponse" matches receiver "response" via the response heuristic.
		{
			ID:          "swift.urlresponse.allheaderfields",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `\.allHeaderFields\s*\[|\.value\s*\(\s*forHTTPHeaderField:`,
			ObjectType:  "HTTPURLResponse",
			MethodName:  "allHeaderFields",
			Description: "HTTP response headers (attacker-controlled in SSRF or cache poisoning scenarios)",
			Assigns:     "return",
		},

		// ── Push notification content payload (CWE-20) ─────────────
		// Matches `content.userInfo` after extracting UNNotificationContent
		// from UNNotificationResponse in UNUserNotificationCenterDelegate.
		{
			ID:          "swift.apns.content.userinfo",
			Category:    taint.SrcNetwork,
			Language:    rules.LangSwift,
			Pattern:     `(?:UNNotificationContent|content)\.userInfo|\.request\.content\.userInfo`,
			ObjectType:  "UNNotificationContent",
			MethodName:  "content.userInfo",
			Description: "APNs push notification content userInfo payload (server-provided, potentially attacker-influenced)",
			Assigns:     "return",
		},

		// ── XPC inter-process message data (CWE-20 / CWE-501) ──────
		// Apple's libxpc <xpc/xpc.h> is the canonical IPC primitive for macOS/iOS
		// privileged helpers, app extensions, daemons, XPC services, and
		// SMJobBless-installed root tools. The receiving process treats incoming
		// xpc_object_t messages as untrusted input from another (potentially
		// non-privileged) process. Real CVEs in this pattern: CVE-2020-9839
		// (CVMS daemon — xpc_dictionary_get_string flowed to dlopen),
		// CVE-2019-8500, CVE-2021-30724. Even after audit_token validation the
		// payload contents remain attacker-controlled.
		//
		// All xpc_dictionary_get_* / xpc_array_get_* / xpc_*_get_* functions
		// are free C functions imported into Swift via the XPC framework, with
		// no receiver — ObjectType "" + the unique `xpc_*_get_*` name suffices.
		{
			ID:          "swift.xpc.dictionary.string",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_string\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_string",
			Description: "XPC dictionary string value from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.int64",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_int64\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_int64",
			Description: "XPC dictionary int64 value from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.uint64",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_uint64\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_uint64",
			Description: "XPC dictionary uint64 value from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.bool",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_bool\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_bool",
			Description: "XPC dictionary bool value from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.double",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_double\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_double",
			Description: "XPC dictionary double value from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.data",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_data\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_data",
			Description: "XPC dictionary raw data bytes from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.value",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_value\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_value",
			Description: "XPC dictionary generic xpc_object_t value from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.array",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_array\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_array",
			Description: "XPC dictionary nested xpc_array from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.dictionary.dictionary",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_dictionary_get_dictionary\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_dictionary_get_dictionary",
			Description: "XPC nested dictionary from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.array.string",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_array_get_string\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_array_get_string",
			Description: "XPC array string element from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.array.value",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_array_get_value\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_array_get_value",
			Description: "XPC array generic xpc_object_t element from sender process (untrusted IPC input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.string.value",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_string_get_string_ptr\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_string_get_string_ptr",
			Description: "XPC string xpc_object_t to char pointer (returns sender-controlled string)",
			Assigns:     "return",
		},
		{
			ID:          "swift.xpc.data.bytes",
			Category:    taint.SrcExternal,
			Language:    rules.LangSwift,
			Pattern:     `xpc_data_get_bytes_ptr\s*\(`,
			ObjectType:  "",
			MethodName:  "xpc_data_get_bytes_ptr",
			Description: "XPC data xpc_object_t to bytes pointer (returns sender-controlled data)",
			Assigns:     "return",
		},

		// --- SQLite.swift / MongoSwift / MySQLNIO result-read sources (second-order injection) ---
		// Swift already models the *write* side of these drivers as injection
		// sinks — swift.sqliteswift.{run,prepare,execute,scalar},
		// swift.mongoswift.collection.{find,findOne,aggregate,...},
		// swift.mysqlnio.simplequery — but not the *read-back* side: an
		// attacker-controlled value persisted by one request and SELECTed by
		// a later one still carries the original taint, and feeding it into a
		// SQL/NoSQL/command/HTML sink without re-validation is second-order
		// injection. Mirrors the cross-language second-order DB-read source
		// wave: java.jedis.* (PR #641), Ruby Mysql2/PG/Mongo (PR #760),
		// Python SQLAlchemy/pymongo (PR #736), C# NoSQL (PR #748), etc.
		//
		// SQLite.swift `Connection` methods are matched via the "Connection"
		// receiver heuristic in tsflow/matcher.go (receiver names db / conn /
		// connection). MongoSwift `MongoCollection` is matched via the
		// "Collection" receiver heuristic (collection / coll / c). MySQLNIO
		// `simpleQuery` on a `MySQLConnection` is matched via the "connection"
		// substring heuristic (conn / connection / db / mysql).
		{
			ID:          "swift.sqliteswift.pluck",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `(?:db|database|conn|connection)\.pluck\s*\(`,
			ObjectType:  "Connection",
			MethodName:  "pluck",
			Description: "SQLite.swift Connection.pluck returns the first matching Row — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqliteswift.prepare.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `(?:db|database|conn|connection)\.prepare\s*\(`,
			ObjectType:  "Connection",
			MethodName:  "prepare",
			Description: "SQLite.swift Connection.prepare returns a Statement / Row sequence over the result set — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqliteswift.scalar.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `(?:db|database|conn|connection)\.scalar\s*\(`,
			ObjectType:  "Connection",
			MethodName:  "scalar",
			Description: "SQLite.swift Connection.scalar returns a single value from the result set — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.sqliteswift.preparerowiterator",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `(?:db|database|conn|connection)\.prepareRowIterator\s*\(`,
			ObjectType:  "Connection",
			MethodName:  "prepareRowIterator",
			Description: "SQLite.swift Connection.prepareRowIterator returns a throwing RowIterator over the result set — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.mongoswift.collection.findone.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.findOne\s*\(`,
			ObjectType:  "Collection",
			MethodName:  "findOne",
			Description: "MongoSwift MongoCollection.findOne returns the matched document — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.mongoswift.collection.aggregate.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `MongoCollection[^;]*\.aggregate\s*\(`,
			ObjectType:  "Collection",
			MethodName:  "aggregate",
			Description: "MongoSwift MongoCollection.aggregate returns a MongoCursor over the pipeline output — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.mongoswift.collection.distinct.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `MongoCollection[^;]*\.distinct\s*\(`,
			ObjectType:  "Collection",
			MethodName:  "distinct",
			Description: "MongoSwift MongoCollection.distinct returns the array of distinct field values — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.mongoswift.collection.findoneandupdate.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.findOneAndUpdate\s*\(`,
			ObjectType:  "Collection",
			MethodName:  "findOneAndUpdate",
			Description: "MongoSwift MongoCollection.findOneAndUpdate returns the matched document — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.mongoswift.collection.findoneanddelete.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `\.findOneAndDelete\s*\(`,
			ObjectType:  "Collection",
			MethodName:  "findOneAndDelete",
			Description: "MongoSwift MongoCollection.findOneAndDelete returns the deleted document — database data, potentially second-order tainted",
			Assigns:     "return",
		},
		{
			ID:          "swift.mysqlnio.simplequery.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangSwift,
			Pattern:     `(?:conn|connection|mysql)\.simpleQuery\s*\(`,
			ObjectType:  "MySQLConnection",
			MethodName:  "simpleQuery",
			Description: "MySQLNIO MySQLConnection.simpleQuery returns the [MySQLRow] result set — database data, potentially second-order tainted",
			Assigns:     "return",
		},

		// --- gRPC Swift v2 (grpc/grpc-swift-2) server-handler sources ---
		// gRPC is a first-class Swift server framework, but its inbound
		// request payload was unmodeled (Go, C++, and Python already carry
		// grpc sources). In the v2 async API a service handler conforming to
		// `ServiceProtocol` / `StreamingServiceProtocol` receives a
		// `ServerRequest<Input>` (or `StreamingServerRequest<Input>`) and
		// reads the client-supplied, SwiftProtobuf-decoded payload via
		// `request.message` (unary) or `request.messages` (the inbound async
		// stream). `request.metadata` carries client-set custom headers. All
		// three are attacker-controlled and routinely flow into SQL/command/
		// path sinks without revalidation. Receiver `request`/`req` matches
		// "ServerRequest" / "StreamingServerRequest" via the request
		// heuristic in matcher.go; the attribute names are gRPC-specific so
		// they don't collide with the generic request-source entries above.
		{
			ID:          "swift.grpc.request.message",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `(?:request|req)\.message\b`,
			ObjectType:  "ServerRequest",
			MethodName:  "message",
			Description: "gRPC Swift v2 ServerRequest.message — the client-supplied, SwiftProtobuf-decoded request payload (untrusted input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.grpc.request.messages",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `(?:request|req)\.messages\b`,
			ObjectType:  "StreamingServerRequest",
			MethodName:  "messages",
			Description: "gRPC Swift v2 StreamingServerRequest.messages — the inbound async stream of client-supplied request messages (untrusted input)",
			Assigns:     "return",
		},
		{
			ID:          "swift.grpc.request.metadata",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `(?:request|req)\.metadata\b`,
			ObjectType:  "ServerRequest",
			MethodName:  "metadata",
			Description: "gRPC Swift v2 ServerRequest.metadata — client-set request metadata (custom headers/trailers), attacker-controlled",
			Assigns:     "return",
		},

		// --- Additional Vapor / Hummingbird / Kitura request sources ---
		{ID: "swift.vapor.req.parameters", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.parameters\b|request\.parameters\b`, ObjectType: "Vapor.Request", MethodName: "parameters", Description: "Vapor Request.parameters — path parameters bound by route pattern", Assigns: "return"},
		{ID: "swift.vapor.req.query", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.query\b|request\.query\b`, ObjectType: "Vapor.Request", MethodName: "query", Description: "Vapor Request.query — URL query parameters", Assigns: "return"},
		{ID: "swift.vapor.req.content", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.content\b|request\.content\b`, ObjectType: "Vapor.Request", MethodName: "content", Description: "Vapor Request.content — decoded request body (JSON / form / multipart)", Assigns: "return"},
		{ID: "swift.vapor.req.headers", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.headers\b|request\.headers\b`, ObjectType: "Vapor.Request", MethodName: "headers", Description: "Vapor Request.headers — HTTP headers", Assigns: "return"},
		{ID: "swift.vapor.req.cookies", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.cookies\b|request\.cookies\b`, ObjectType: "Vapor.Request", MethodName: "cookies", Description: "Vapor Request.cookies — Cookie header parsed", Assigns: "return"},
		{ID: "swift.vapor.req.url", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.url\b|request\.url\b`, ObjectType: "Vapor.Request", MethodName: "url", Description: "Vapor Request.url — full URL components", Assigns: "return"},
		{ID: "swift.vapor.req.body", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.body\b|request\.body\b`, ObjectType: "Vapor.Request", MethodName: "body", Description: "Vapor Request.body — raw request body buffer", Assigns: "return"},

		// Hummingbird (Swift on Server / NIO-based)
		{ID: "swift.hummingbird.request.uri", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.uri\b`, ObjectType: "Hummingbird.HBRequest", MethodName: "uri", Description: "Hummingbird HBRequest.uri — full URI", Assigns: "return"},
		{ID: "swift.hummingbird.request.headers", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.headers\b`, ObjectType: "Hummingbird.HBRequest", MethodName: "headers", Description: "Hummingbird HBRequest.headers — HTTP headers", Assigns: "return"},
		{ID: "swift.hummingbird.request.body", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.body\b`, ObjectType: "Hummingbird.HBRequest", MethodName: "body", Description: "Hummingbird HBRequest.body — request body buffer", Assigns: "return"},
		{ID: "swift.hummingbird.request.parameters", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.parameters\b`, ObjectType: "Hummingbird.HBRequest", MethodName: "parameters", Description: "Hummingbird HBRequest.parameters — path parameters", Assigns: "return"},

		// Kitura (legacy IBM Swift framework)
		{ID: "swift.kitura.request.parameters", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.parameters\b|request\.parameters\b`, ObjectType: "Kitura.RouterRequest", MethodName: "parameters", Description: "Kitura RouterRequest.parameters — path parameters", Assigns: "return"},
		{ID: "swift.kitura.request.query_parameters", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.queryParameters\b|request\.queryParameters\b`, ObjectType: "Kitura.RouterRequest", MethodName: "queryParameters", Description: "Kitura RouterRequest.queryParameters — URL query params", Assigns: "return"},
		{ID: "swift.kitura.request.body", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `req\.body\b|request\.body\b`, ObjectType: "Kitura.RouterRequest", MethodName: "body", Description: "Kitura RouterRequest.body — parsed request body", Assigns: "return"},

		// --- Swifter (httpswift/swifter — tiny embedded HTTP server, ~6k stars) ---
		// Route handlers register a closure `server["/path"] = { request in ... }`
		// receiving an HttpRequest whose properties expose raw, un-decoded,
		// attacker-controlled input. Property names are Swifter-specific
		// (`.queryParams`, `.params[...]`, raw `[UInt8]` `.body`) so the patterns
		// do not collide with Vapor (`.query`/`.parameters`) or Kitura
		// (`.queryParameters`). `.params`/`.headers`/`.body`/`.path`/`.address`
		// are receiver-scoped to Swifter.HttpRequest (the tsflow matcher's
		// receiver heuristic maps "request"/"req" onto an ObjectType containing
		// "request"), so they do not over-match the same bare accessor on other
		// frameworks' request objects.
		{ID: "swift.swifter.request.queryParams", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `\.queryParams\b`, ObjectType: "Swifter.HttpRequest", MethodName: "queryParams", Description: "Swifter HttpRequest.queryParams — URL query parameters as [(String, String)] (raw, undecoded user input)", Assigns: "return"},
		{ID: "swift.swifter.request.params", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `\.params\[`, ObjectType: "Swifter.HttpRequest", MethodName: "params", Description: "Swifter HttpRequest.params — path parameters bound by route pattern (e.g. request.params[\":name\"])", Assigns: "return"},
		{ID: "swift.swifter.request.body", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.body\b`, ObjectType: "Swifter.HttpRequest", MethodName: "body", Description: "Swifter HttpRequest.body — raw request body bytes ([UInt8]), entirely attacker-controlled", Assigns: "return"},
		{ID: "swift.swifter.request.headers", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `\.headers\[`, ObjectType: "Swifter.HttpRequest", MethodName: "headers", Description: "Swifter HttpRequest.headers — HTTP request header values keyed by name", Assigns: "return"},
		{ID: "swift.swifter.request.path", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.path\b`, ObjectType: "Swifter.HttpRequest", MethodName: "path", Description: "Swifter HttpRequest.path — raw request path string (attacker-controlled URL path)", Assigns: "return"},
		{ID: "swift.swifter.request.address", Category: taint.SrcUserInput, Language: rules.LangSwift, Pattern: `request\.address\b`, ObjectType: "Swifter.HttpRequest", MethodName: "address", Description: "Swifter HttpRequest.address — client-supplied remote address (spoofable via proxy headers)", Assigns: "return"},
	}
}
