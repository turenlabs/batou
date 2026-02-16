package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
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
	}
}
