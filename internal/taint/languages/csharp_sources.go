package languages

import (
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
)

func (c *CSharpCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- ASP.NET Core: HttpContext.Request ---
		{
			ID:          "csharp.http.request.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Query\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Query",
			Description: "HTTP query string parameter",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.form",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Form\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Form",
			Description: "HTTP form data",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Headers\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Headers",
			Description: "HTTP request header",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.cookies",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Cookies\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Cookies",
			Description: "HTTP cookie value",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Body|Request\.BodyReader`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Body",
			Description: "HTTP request body stream",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.querystring",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.QueryString`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.QueryString",
			Description: "Raw HTTP query string",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Path|Request\.PathBase`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Path",
			Description: "HTTP request path",
			Assigns:     "return",
		},

		// --- ASP.NET Core: Route data ---
		{
			ID:          "csharp.http.routedata",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `RouteData\.Values\[`,
			ObjectType:  "RouteData",
			MethodName:  "RouteData.Values",
			Description: "URL route parameter",
			Assigns:     "return",
		},

		// --- ASP.NET MVC: Model binding ---
		{
			ID:          "csharp.mvc.modelstate",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `ModelState\[`,
			ObjectType:  "ModelStateDictionary",
			MethodName:  "ModelState",
			Description: "Model state value from form binding",
			Assigns:     "return",
		},
		{
			ID:          "csharp.mvc.action.parameter",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\[FromQuery\]|\[FromBody\]|\[FromForm\]|\[FromRoute\]|\[FromHeader\]`,
			ObjectType:  "ASP.NET MVC",
			MethodName:  "Action parameter binding",
			Description: "Model-bound action parameter from HTTP request",
			Assigns:     "return",
		},

		// --- File uploads ---
		{
			ID:          "csharp.http.formfile",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `IFormFile|Request\.Form\.Files`,
			ObjectType:  "IFormFile",
			MethodName:  "IFormFile",
			Description: "Uploaded file from HTTP request",
			Assigns:     "return",
		},

		// --- StreamReader (reading untrusted streams) ---
		{
			ID:          "csharp.io.streamreader",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `StreamReader.*\.ReadToEnd\(|StreamReader.*\.ReadLine\(|StreamReader.*\.ReadAsync\(`,
			ObjectType:  "StreamReader",
			MethodName:  "ReadToEnd/ReadLine",
			Description: "Stream reader data from potentially untrusted source",
			Assigns:     "return",
		},
		{
			ID:          "csharp.io.streamreader.new",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `new\s+StreamReader\(`,
			ObjectType:  "StreamReader",
			MethodName:  "new StreamReader",
			Description: "StreamReader wrapping potentially untrusted stream",
			Assigns:     "return",
		},

		// --- Environment variables ---
		{
			ID:          "csharp.environment.getenvironmentvariable",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangCSharp,
			Pattern:     `Environment\.GetEnvironmentVariable\(`,
			ObjectType:  "System.Environment",
			MethodName:  "GetEnvironmentVariable",
			Description: "Environment variable value",
			Assigns:     "return",
		},

		// --- Command-line arguments ---
		{
			ID:          "csharp.environment.commandline",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangCSharp,
			Pattern:     `Environment\.GetCommandLineArgs\(|Environment\.CommandLine`,
			ObjectType:  "System.Environment",
			MethodName:  "GetCommandLineArgs",
			Description: "Command-line arguments",
			Assigns:     "return",
		},
		{
			ID:          "csharp.main.args",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangCSharp,
			Pattern:     `static\s+.*\s+Main\s*\(\s*string\s*\[\]\s*args\s*\)`,
			ObjectType:  "Program",
			MethodName:  "Main args",
			Description: "Main method string arguments",
			Assigns:     "return",
		},

		// --- Console input ---
		{
			ID:          "csharp.console.readline",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Console\.ReadLine\(`,
			ObjectType:  "System.Console",
			MethodName:  "ReadLine",
			Description: "Console input from user",
			Assigns:     "return",
		},

		// --- Database results ---
		{
			ID:          "csharp.data.datareader",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ExecuteReader\(|reader\[|reader\.GetString\(|reader\.GetValue\(`,
			ObjectType:  "SqlDataReader",
			MethodName:  "ExecuteReader/Get*",
			Description: "Database query result data",
			Assigns:     "return",
		},

		// --- Deserialization ---
		{
			ID:          "csharp.json.deserialize",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCSharp,
			Pattern:     `JsonConvert\.DeserializeObject|JsonSerializer\.Deserialize|System\.Text\.Json\.JsonSerializer\.Deserialize`,
			ObjectType:  "JsonConvert/JsonSerializer",
			MethodName:  "DeserializeObject/Deserialize",
			Description: "JSON deserialized data from untrusted source",
			Assigns:     "return",
		},

		// --- HttpClient response (external data) ---
		{
			ID:          "csharp.httpclient.response",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReadAsStringAsync\(|\.ReadAsStreamAsync\(|\.Content\.ReadAs`,
			ObjectType:  "HttpResponseMessage",
			MethodName:  "ReadAsStringAsync",
			Description: "HTTP response content from external service",
			Assigns:     "return",
		},

		// --- Azure / Cloud SDK ---
		{
			ID:          "csharp.azure.functions.trigger",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\[HttpTrigger\]|\[BlobTrigger\]|\[QueueTrigger\]|\[ServiceBusTrigger\]`,
			ObjectType:  "Azure Functions",
			MethodName:  "Azure trigger binding",
			Description: "Azure Functions trigger data from external source",
			Assigns:     "return",
		},

		// --- SignalR hub ---
		{
			ID:          "csharp.signalr.hubcontext",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `HubCallerContext|Context\.ConnectionId|Context\.User`,
			ObjectType:  "SignalR",
			MethodName:  "HubCallerContext",
			Description: "SignalR hub caller context data",
			Assigns:     "return",
		},

		// --- Minimal API parameters ---
		{
			ID:          "csharp.minimalapi.parameter",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\[FromQuery\]|\[FromBody\]|\[FromRoute\]|\[FromHeader\]|\[AsParameters\]`,
			ObjectType:  "MinimalAPI",
			MethodName:  "minimal API parameter binding",
			Description: "ASP.NET minimal API parameter binding",
			Assigns:     "return",
		},

		// --- gRPC ---
		{
			ID:          "csharp.grpc.request",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `ServerCallContext|\.RequestHeaders|Grpc\.Core\.ServerCallContext`,
			ObjectType:  "gRPC",
			MethodName:  "ServerCallContext",
			Description: "gRPC server call context and request data",
			Assigns:     "return",
		},

		// --- Configuration (potentially tainted) ---
		{
			ID:          "csharp.configuration.getvalue",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `Configuration\[|IConfiguration.*GetValue\s*\(|_config\[`,
			ObjectType:  "IConfiguration",
			MethodName:  "Configuration[key]",
			Description: "Configuration value from potentially untrusted source",
			Assigns:     "return",
		},

		// --- XML deserialization ---
		{
			ID:          "csharp.xml.deserialize",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCSharp,
			Pattern:     `XmlSerializer.*\.Deserialize\(|DataContractSerializer.*\.ReadObject\(`,
			ObjectType:  "XmlSerializer",
			MethodName:  "Deserialize/ReadObject",
			Description: "XML deserialized data from untrusted source",
			Assigns:     "return",
		},

		// --- Additional ASP.NET sources ---
		{
			ID:          "csharp.http.request.rawurl",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.RawUrl|HttpContext\.Request\.Path`,
			ObjectType:  "HttpRequest",
			MethodName:  "RawUrl/Path",
			Description: "HTTP request raw URL or path",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.useragent",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Headers\[.*User-Agent|HttpContext\.Request\.Headers`,
			ObjectType:  "HttpRequest",
			MethodName:  "UserAgent/Headers",
			Description: "HTTP request User-Agent or other headers",
			Assigns:     "return",
		},
		{
			ID:          "csharp.file.readalltext",
			Category:    taint.SrcFileRead,
			Language:    rules.LangCSharp,
			Pattern:     `File\.ReadAllText\s*\(|File\.ReadAllLines\s*\(|File\.ReadAllBytes\s*\(`,
			ObjectType:  "System.IO.File",
			MethodName:  "ReadAllText/Lines/Bytes",
			Description: "File contents from System.IO.File read methods",
			Assigns:     "return",
		},
	}
}
