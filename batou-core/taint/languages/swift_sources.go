package languages

import (
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
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
			Pattern:     `\.text(?:\s*\?\?\s*|\s*!)?\s*$|textField\.text|TextField\.text|input\.text|field\.text`,
			ObjectType:  "UITextField",
			MethodName:  "text",
			Description: "Text field user input",
			Assigns:     "return",
		},
		{
			ID:          "swift.uitextview.text",
			Category:    taint.SrcUserInput,
			Language:    rules.LangSwift,
			Pattern:     `textView\.text|UITextView.*\.text`,
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

		// --- Bundle resources ---
		{
			ID:          "swift.bundle.resource",
			Category:    taint.SrcFileRead,
			Language:    rules.LangSwift,
			Pattern:     `Bundle\.main\.(?:path|url)\(forResource:|Bundle\.main\.resourcePath`,
			ObjectType:  "Bundle",
			MethodName:  "path/url(forResource:)",
			Description: "Bundle resource path",
			Assigns:     "return",
		},

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

		// --- File read ---
		{
			ID:          "swift.string.contentsoffile",
			Category:    taint.SrcFileRead,
			Language:    rules.LangSwift,
			Pattern:     `String\(\s*contentsOfFile:|String\(\s*contentsOf:`,
			ObjectType:  "String",
			MethodName:  "String(contentsOfFile:)",
			Description: "File contents read as string",
			Assigns:     "return",
		},
		{
			ID:          "swift.data.contentsof",
			Category:    taint.SrcFileRead,
			Language:    rules.LangSwift,
			Pattern:     `Data\(\s*contentsOf:`,
			ObjectType:  "Data",
			MethodName:  "Data(contentsOf:)",
			Description: "File or URL contents read as Data",
			Assigns:     "return",
		},

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
	}
}
