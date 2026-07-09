package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
		// --- SLICE A (pure catalog, parity with Request.QueryString above) ---
		// The umbrella `Request.Params[...]` and `Request.ServerVariables[...]`
		// collections are the classic pre-Core WebForms/MVC5 user-input idioms,
		// yet only the named sub-collections (Query/Form/Cookies/Headers/...) were
		// catalogued. Request.Params merges QueryString+Form+Cookies+ServerVariables
		// and ServerVariables exposes client-controlled CGI/header values — both are
		// unambiguously HttpRequest user input (near-zero FP). The dotted MethodName
		// + existing csharpAttrPathHasDottedSuffix routing make both the bare
		// (`Request.Params["x"]`) and prefixed (`context.Request.Params["x"]`) forms
		// match with no engine change, exactly like Request.QueryString.
		{
			ID:          "csharp.http.request.params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Params\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Params",
			Description: "HTTP request umbrella parameter collection (HttpRequest.Params — merges query/form/cookies/server vars)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.http.request.servervariables",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.ServerVariables\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.ServerVariables",
			Description: "HTTP request server/CGI variables (HttpRequest.ServerVariables — includes client-controlled headers)",
			Assigns:     "return",
		},
		// --- SLICE B (HttpRequest.Item indexer — bare `Request["key"]`) ---
		// The umbrella indexer `Request["key"]` (HttpRequest.Item) is THE dominant
		// pre-Core user-input idiom (WebGoat.NET ProductDetails/Orders/ReflectedXSS
		// all use bare `Request["x"]`). As a single-component MethodName it cannot
		// rely on the dotted-suffix routing; it is resolved structurally by the
		// C#-gated bare-identifier case in walker.go (findSourceInExpr) for the
		// bare form and by the C#-gated receiver branch in matchSourceAttr for the
		// `context.Request["x"]` / `this.Request["x"]` member-access forms. Both
		// routes are LangCSharp-bound and keyed on the capital-`Request` convention.
		{
			ID:          "csharp.http.request.item",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\bRequest\s*\[`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request",
			Description: "HTTP request umbrella indexer (HttpRequest.Item — Request[\"key\"])",
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

		// --- Archive entry names (ZipSlip / CWE-22) ---
		// A ZipArchiveEntry.FullName is attacker-controlled archive metadata: a
		// malicious zip can carry entry names like "../../etc/passwd". When the
		// name flows into an extraction sink (ExtractToFile / a path passed to
		// ExtractToDirectory) without a containment check, the archive can write
		// outside the intended directory (ZipSlip). ObjectType is relaxed to ""
		// because .FullName is distinctive on archive entries and the loop
		// variable's declared type is rarely visible to the walker.
		{
			ID:          "csharp.ziparchive.fullname",
			Category:    taint.SrcFileRead,
			Language:    rules.LangCSharp,
			Pattern:     `\.FullName\b`,
			ObjectType:  "",
			MethodName:  "FullName",
			Description: "ZipArchiveEntry.FullName — attacker-controlled archive entry name (ZipSlip source)",
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
			Pattern:     `\.ExecuteReader\(|(?:^|[^\w])reader\[|reader\.GetString\(|reader\.GetValue\(`,
			ObjectType:  "SqlDataReader",
			MethodName:  "ExecuteReader/Get*",
			Description: "Database query result data",
			Assigns:     "return",
		},
		// --- ADO.NET DbDataReader typed getters (second-order injection) ---
		// The legacy csharp.data.datareader entry above relies on a "Get*"
		// wildcard MethodName that the tsflow matcher cannot expand, so the
		// individual typed getters never fire on idiomatic receivers
		// (`reader`/`dr`/`rdr`). These entries register the concrete
		// string/object-returning getters that surface attacker-controlled data
		// stored in the database (CWE-89 second-order SQLi, stored XSS, etc.).
		// ObjectType "DbDataReader" is the ADO.NET base class, covering
		// SqlDataReader, NpgsqlDataReader, MySqlDataReader, SqliteDataReader,
		// OleDbDataReader. Receiver matching is handled by the tsflow alias
		// (matcher.go) that maps reader/dr/rdr to "...datareader" ObjectTypes.
		{
			ID:          "csharp.data.datareader.getstring",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetString\s*\(`,
			ObjectType:  "DbDataReader",
			MethodName:  "GetString",
			Description: "Database string column read via DbDataReader.GetString (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.getvalue",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetValue\s*\(`,
			ObjectType:  "DbDataReader",
			MethodName:  "GetValue",
			Description: "Database column value read via DbDataReader.GetValue (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.getfieldvalue",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetFieldValue\s*<`,
			ObjectType:  "DbDataReader",
			MethodName:  "GetFieldValue",
			Description: "Database typed column read via DbDataReader.GetFieldValue<T> (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.getfieldvalueasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetFieldValueAsync\s*<`,
			ObjectType:  "DbDataReader",
			MethodName:  "GetFieldValueAsync",
			Description: "Database typed column read via DbDataReader.GetFieldValueAsync<T> (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.gettextreader",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetTextReader\s*\(`,
			ObjectType:  "DbDataReader",
			MethodName:  "GetTextReader",
			Description: "Database text column read via DbDataReader.GetTextReader (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.getsqlstring",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetSqlString\s*\(`,
			ObjectType:  "SqlDataReader",
			MethodName:  "GetSqlString",
			Description: "Database SqlString column read via SqlDataReader.GetSqlString (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.getsqlvalue",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetSqlValue\s*\(`,
			ObjectType:  "SqlDataReader",
			MethodName:  "GetSqlValue",
			Description: "Database SqlValue column read via SqlDataReader.GetSqlValue (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.datareader.getproviderspecificvalue",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:reader|dr|rdr)\.GetProviderSpecificValue\s*\(`,
			ObjectType:  "DbDataReader",
			MethodName:  "GetProviderSpecificValue",
			Description: "Database provider-specific column read via DbDataReader.GetProviderSpecificValue (second-order injection source)",
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

		// --- Blazor ---
		{
			ID:          "csharp.blazor.parameter",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\[Parameter\]|\[SupplyParameterFromQuery\]|\[CascadingParameter\]`,
			ObjectType:  "Blazor",
			MethodName:  "[Parameter]/[SupplyParameterFromQuery]",
			Description: "Blazor component parameter from URL or parent component",
			Assigns:     "return",
		},
		{
			ID:          "csharp.blazor.navigationmanager",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `NavigationManager\.Uri|NavigationManager\.ToAbsoluteUri`,
			ObjectType:  "NavigationManager",
			MethodName:  "NavigationManager.Uri",
			Description: "Blazor NavigationManager URI (contains user-controlled URL)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.blazor.editcontext",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `EditContext\.Model|EditForm.*Model`,
			ObjectType:  "EditContext",
			MethodName:  "EditContext.Model",
			Description: "Blazor EditForm model bound to user input",
			Assigns:     "return",
		},

		// --- ASP.NET Core: Route values ---
		{
			ID:          "csharp.http.request.routevalues",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.RouteValues\[|RouteData\.Values\[|HttpContext\.GetRouteValue\s*\(`,
			ObjectType:  "HttpRequest",
			MethodName:  "RouteValues/GetRouteValue",
			Description: "HTTP route parameter value",
			Assigns:     "return",
		},

		// --- ASP.NET Core: Session ---
		{
			ID:          "csharp.http.session.getstring",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `HttpContext\.Session\.GetString\s*\(|Session\.GetString\s*\(|Session\.GetInt32\s*\(`,
			ObjectType:  "ISession",
			MethodName:  "Session.GetString/GetInt32",
			Description: "Session data (may contain user-controlled values)",
			Assigns:     "return",
		},

		// --- ASP.NET Core: TempData ---
		{
			ID:          "csharp.mvc.tempdata",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `TempData\[`,
			ObjectType:  "ITempDataDictionary",
			MethodName:  "TempData[]",
			Description: "Temp data dictionary (may contain user-controlled values from previous request)",
			Assigns:     "return",
		},

		// --- ASP.NET Core: Request content type/method ---
		{
			ID:          "csharp.http.request.contenttype",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.ContentType`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.ContentType",
			Description: "HTTP request Content-Type header (user-controllable)",
			Assigns:     "return",
		},

		// --- Host header injection ---
		{
			ID:          "csharp.http.request.host",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `Request\.Host|HttpContext\.Request\.Host`,
			ObjectType:  "HttpRequest",
			MethodName:  "Request.Host",
			Description: "HTTP Host header (user-controllable, used in password reset poisoning)",
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

		// --- Network: HttpClient direct content retrieval ---
		{
			ID:          "csharp.httpclient.getstringasync",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetStringAsync\s*\(|\.GetStreamAsync\s*\(|\.GetByteArrayAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "GetStringAsync/GetStreamAsync/GetByteArrayAsync",
			Description: "HttpClient direct content retrieval from external URL",
			Assigns:     "return",
		},
		// --- Network: WebClient (legacy, still common in production) ---
		{
			ID:          "csharp.webclient.downloadstring",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `\.DownloadString\s*\(|\.DownloadData\s*\(|\.DownloadStringTaskAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "DownloadString/DownloadData",
			Description: "WebClient download from external URL (legacy API)",
			Assigns:     "return",
		},
		// --- Network: HttpWebRequest/WebResponse (legacy HTTP API) ---
		{
			ID:          "csharp.httpwebrequest.getresponse",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetResponse\s*\(|\.GetResponseStream\s*\(`,
			ObjectType:  "HttpWebRequest",
			MethodName:  "GetResponse/GetResponseStream",
			Description: "HttpWebRequest response data (legacy HTTP API)",
			Assigns:     "return",
		},
		// --- Network: WebSocket data reception ---
		{
			ID:          "csharp.websocket.receiveasync",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `(?:WebSocket|webSocket|ws|socket)\.ReceiveAsync\s*\(`,
			ObjectType:  "WebSocket",
			MethodName:  "ReceiveAsync",
			Description: "WebSocket data reception (untrusted peer data)",
			Assigns:     "return",
		},
		// --- Network: TcpClient / NetworkStream ---
		{
			ID:          "csharp.tcpclient.networkstream",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCSharp,
			Pattern:     `TcpClient.*\.GetStream\s*\(|NetworkStream.*\.Read(?:Async)?\s*\(`,
			ObjectType:  "TcpClient",
			MethodName:  "GetStream/NetworkStream.Read",
			Description: "TCP network stream data (raw socket input)",
			Assigns:     "return",
		},

		// --- Database: Dapper query results ---
		{
			ID:          "csharp.dapper.query",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.Query\s*<|\.QueryFirst\s*<|\.QuerySingle\s*<|\.QueryFirstOrDefault\s*<|\.QuerySingleOrDefault\s*<`,
			ObjectType:  "IDbConnection",
			MethodName:  "Query/QueryFirst/QuerySingle",
			Description: "Dapper query result (second-order injection source)",
			Assigns:     "return",
		},
		// --- Database: ADO.NET ExecuteScalar ---
		{
			ID:          "csharp.data.executescalar",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ExecuteScalar\s*\(`,
			ObjectType:  "",
			MethodName:  "ExecuteScalar",
			Description: "ADO.NET scalar database result value",
			Assigns:     "return",
		},

		// --- Database: ADO.NET async ---
		{
			ID:          "csharp.data.executereaderasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ExecuteReaderAsync\s*\(`,
			ObjectType:  "SqlCommand",
			MethodName:  "ExecuteReaderAsync",
			Description: "ADO.NET async database reader (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.data.executescalarasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ExecuteScalarAsync\s*\(`,
			ObjectType:  "SqlCommand",
			MethodName:  "ExecuteScalarAsync",
			Description: "ADO.NET async scalar database result (second-order injection source)",
			Assigns:     "return",
		},

		// --- Database: Dapper async query results ---
		{
			ID:          "csharp.dapper.queryasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.QueryAsync\s*<|\.QueryFirstAsync\s*<|\.QuerySingleAsync\s*<|\.QueryFirstOrDefaultAsync\s*<|\.QuerySingleOrDefaultAsync\s*<`,
			ObjectType:  "IDbConnection",
			MethodName:  "QueryAsync/QueryFirstAsync/QuerySingleAsync",
			Description: "Dapper async query result (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.dapper.querymultiple",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.QueryMultiple\s*\(|\.QueryMultipleAsync\s*\(`,
			ObjectType:  "IDbConnection",
			MethodName:  "QueryMultiple/QueryMultipleAsync",
			Description: "Dapper multi-result set query (second-order injection source)",
			Assigns:     "return",
		},

		// --- Database: Entity Framework Core ---
		{
			ID:          "csharp.efcore.findasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.FindAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "FindAsync",
			Description: "EF Core primary key lookup — entity loaded from database",
			Assigns:     "return",
		},
		{
			ID:          "csharp.efcore.tolistasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ToListAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "ToListAsync",
			Description: "EF Core query materialization — entities loaded from database",
			Assigns:     "return",
		},
		{
			ID:          "csharp.efcore.firstasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.FirstAsync\s*\(|\.FirstOrDefaultAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "FirstAsync/FirstOrDefaultAsync",
			Description: "EF Core single-result query — entity loaded from database",
			Assigns:     "return",
		},
		{
			ID:          "csharp.efcore.singleasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.SingleAsync\s*\(|\.SingleOrDefaultAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "SingleAsync/SingleOrDefaultAsync",
			Description: "EF Core exact-one-result query — entity loaded from database",
			Assigns:     "return",
		},

		// --- File: async read variants ---
		{
			ID:          "csharp.file.readalltextasync",
			Category:    taint.SrcFileRead,
			Language:    rules.LangCSharp,
			Pattern:     `File\.ReadAllTextAsync\s*\(|File\.ReadAllLinesAsync\s*\(|File\.ReadAllBytesAsync\s*\(`,
			ObjectType:  "System.IO.File",
			MethodName:  "ReadAllTextAsync/ReadAllLinesAsync/ReadAllBytesAsync",
			Description: "Async file read operations",
			Assigns:     "return",
		},
		// --- File: OpenRead / Open ---
		{
			ID:          "csharp.file.openread",
			Category:    taint.SrcFileRead,
			Language:    rules.LangCSharp,
			Pattern:     `File\.OpenRead\s*\(|File\.Open\s*\(`,
			ObjectType:  "System.IO.File",
			MethodName:  "OpenRead/Open",
			Description: "File open for reading (returns FileStream)",
			Assigns:     "return",
		},
		// --- File: BinaryReader ---
		{
			ID:          "csharp.io.binaryreader",
			Category:    taint.SrcFileRead,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReadString\s*\(\s*\)|\.ReadBytes\s*\(`,
			ObjectType:  "",
			MethodName:  "ReadString/ReadBytes",
			Description: "Binary file reader data (BinaryReader)",
			Assigns:     "return",
		},

		// --- Deserialization: BinaryFormatter (CWE-502, removed in .NET 9) ---
		{
			ID:          "csharp.binaryformatter.deserialize",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCSharp,
			Pattern:     `BinaryFormatter.*\.Deserialize\s*\(`,
			ObjectType:  "BinaryFormatter",
			MethodName:  "Deserialize",
			Description: "BinaryFormatter deserialized data (CWE-502, removed in .NET 9)",
			Assigns:     "return",
		},
		// --- Deserialization: SoapFormatter (CWE-502) ---
		{
			ID:          "csharp.soapformatter.deserialize.source",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCSharp,
			Pattern:     `SoapFormatter.*\.Deserialize\s*\(`,
			ObjectType:  "SoapFormatter",
			MethodName:  "Deserialize",
			Description: "SoapFormatter deserialized data (CWE-502)",
			Assigns:     "return",
		},
		// --- Deserialization: MessagePack ---
		{
			ID:          "csharp.messagepack.deserialize",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCSharp,
			Pattern:     `MessagePackSerializer\.Deserialize\s*[<(]`,
			ObjectType:  "MessagePackSerializer",
			MethodName:  "Deserialize",
			Description: "MessagePack deserialization (dangerous in typeless mode)",
			Assigns:     "return",
		},
		// --- Deserialization: YamlDotNet ---
		{
			ID:          "csharp.yaml.deserialize",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCSharp,
			Pattern:     `(?:deserializer|yamlDeserializer)\.Deserialize\s*[<(]`,
			ObjectType:  "Deserializer",
			MethodName:  "Deserialize",
			Description: "YamlDotNet YAML deserialization",
			Assigns:     "return",
		},

		// --- Azure Service Bus messaging ---
		{
			ID:          "csharp.azure.servicebus.body",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `(?:ServiceBusReceivedMessage|receivedMessage|sbMessage)\.Body`,
			ObjectType:  "",
			MethodName:  "Body",
			Description: "Azure Service Bus message body (BinaryData from queue/topic)",
			Assigns:     "return",
		},

		// --- Azure Queue Storage ---
		{
			ID:          "csharp.azure.queue.body",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `QueueMessage.*\.Body|QueueMessage.*\.MessageText`,
			ObjectType:  "QueueMessage",
			MethodName:  "Body/MessageText",
			Description: "Azure Queue Storage message body",
			Assigns:     "return",
		},

		// --- Azure Event Hubs ---
		{
			ID:          "csharp.azure.eventhub.body",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `(?:EventData|eventData)\.EventBody`,
			ObjectType:  "EventData",
			MethodName:  "EventBody",
			Description: "Azure Event Hub event body (BinaryData payload)",
			Assigns:     "return",
		},

		// --- Azure Event Grid ---
		{
			ID:          "csharp.azure.eventgrid.data",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `(?:EventGridEvent|eventGridEvent)\.Data|(?:CloudEvent|cloudEvent)\.Data`,
			ObjectType:  "EventGridEvent",
			MethodName:  "Data",
			Description: "Azure Event Grid event data payload",
			Assigns:     "return",
		},

		// --- RabbitMQ (.NET client) ---
		{
			ID:          "csharp.rabbitmq.body",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `BasicDeliverEventArgs.*\.Body`,
			ObjectType:  "",
			MethodName:  "Body",
			Description: "RabbitMQ message body (ReadOnlyMemory<byte> from queue)",
			Assigns:     "return",
		},

		// --- MassTransit ---
		{
			ID:          "csharp.masstransit.message",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ConsumeContext.*\.Message`,
			ObjectType:  "ConsumeContext",
			MethodName:  "Message",
			Description: "MassTransit consumer message payload (untrusted bus data)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.masstransit.context.headers",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ConsumeContext.*\.Headers`,
			ObjectType:  "ConsumeContext",
			MethodName:  "Headers",
			Description: "MassTransit ConsumeContext.Headers — sender-controlled message headers from the bus",
			Assigns:     "return",
		},
		{
			ID:          "csharp.masstransit.context.correlationid",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ConsumeContext.*\.CorrelationId`,
			ObjectType:  "ConsumeContext",
			MethodName:  "CorrelationId",
			Description: "MassTransit ConsumeContext.CorrelationId — sender-supplied correlation identifier",
			Assigns:     "return",
		},
		{
			ID:          "csharp.masstransit.context.sourceaddress",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ConsumeContext.*\.SourceAddress`,
			ObjectType:  "ConsumeContext",
			MethodName:  "SourceAddress",
			Description: "MassTransit ConsumeContext.SourceAddress — sender-supplied source endpoint URI",
			Assigns:     "return",
		},

		// --- NServiceBus (IMessageHandlerContext) ---
		{
			ID:          "csharp.nservicebus.context.headers",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `IMessageHandlerContext.*\.Headers|context\.Headers\s*\[`,
			ObjectType:  "IMessageHandlerContext",
			MethodName:  "Headers",
			Description: "NServiceBus IMessageHandlerContext.Headers — sender-controlled message headers dictionary",
			Assigns:     "return",
		},
		{
			ID:          "csharp.nservicebus.context.messageid",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `IMessageHandlerContext.*\.MessageId`,
			ObjectType:  "IMessageHandlerContext",
			MethodName:  "MessageId",
			Description: "NServiceBus IMessageHandlerContext.MessageId — sender-supplied message identifier",
			Assigns:     "return",
		},
		{
			ID:          "csharp.nservicebus.context.replytoaddress",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `IMessageHandlerContext.*\.ReplyToAddress`,
			ObjectType:  "IMessageHandlerContext",
			MethodName:  "ReplyToAddress",
			Description: "NServiceBus IMessageHandlerContext.ReplyToAddress — sender-supplied reply destination",
			Assigns:     "return",
		},

		// --- Confluent Kafka (.NET) ---
		{
			ID:          "csharp.kafka.consume.value",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `(?:ConsumeResult|consumeResult|result)\.Message\.Value`,
			ObjectType:  "ConsumeResult",
			MethodName:  "Message.Value",
			Description: "Kafka consumer message value (Confluent.Kafka)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.kafka.consume.key",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `(?:ConsumeResult|consumeResult|result)\.Message\.Key`,
			ObjectType:  "ConsumeResult",
			MethodName:  "Message.Key",
			Description: "Kafka consumer message key (Confluent.Kafka)",
			Assigns:     "return",
		},

		// --- StackExchange.Redis ---
		{
			ID:          "csharp.redis.stringget",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.StringGet(?:Async)?\s*\(|\.HashGet(?:Async)?\s*\(|\.HashGetAll(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "StringGet/HashGet",
			Description: "Redis string/hash read (StackExchange.Redis cached data)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.listrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ListRange(?:Async)?\s*\(|\.SetMembers(?:Async)?\s*\(|\.SortedSetRangeByScore(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "ListRange/SetMembers",
			Description: "Redis list/set read (StackExchange.Redis cached data)",
			Assigns:     "return",
		},
		// Additional StackExchange.Redis read commands. Each reads previously-stored
		// data from Redis; the returned bytes/strings carry user-controlled taint
		// from whatever earlier write put them there (second-order taint). Sync and
		// async variants are packed into MethodName so tsflow registers both.
		{
			ID:          "csharp.redis.hashkeys",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.HashKeys(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "HashKeys/HashKeysAsync",
			Description: "Redis hash field-name read (StackExchange.Redis HKEYS)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.hashvalues",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.HashValues(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "HashValues/HashValuesAsync",
			Description: "Redis hash value read (StackExchange.Redis HVALS)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.hashgetall",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.HashGetAll(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "HashGetAll/HashGetAllAsync",
			Description: "Redis full-hash read (StackExchange.Redis HGETALL)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.hashscan",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.HashScan(?:NoValues)?(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "HashScan/HashScanAsync/HashScanNoValues/HashScanNoValuesAsync",
			Description: "Redis incremental hash enumeration (StackExchange.Redis HSCAN)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.hashrandomfield",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.HashRandomField(?:s)?(?:WithValues)?(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "HashRandomField/HashRandomFieldAsync/HashRandomFields/HashRandomFieldsAsync/HashRandomFieldsWithValues/HashRandomFieldsWithValuesAsync",
			Description: "Redis random-hash-field read (StackExchange.Redis HRANDFIELD)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.listgetbyindex",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ListGetByIndex(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "ListGetByIndex/ListGetByIndexAsync",
			Description: "Redis list element read (StackExchange.Redis LINDEX)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.listleftpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ListLeftPop(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "ListLeftPop/ListLeftPopAsync",
			Description: "Redis list head pop (StackExchange.Redis LPOP)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.listrightpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ListRightPop(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "ListRightPop/ListRightPopAsync",
			Description: "Redis list tail pop (StackExchange.Redis RPOP)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.setrandommember",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.SetRandomMember(?:s)?(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "SetRandomMember/SetRandomMemberAsync/SetRandomMembers/SetRandomMembersAsync",
			Description: "Redis random set member read (StackExchange.Redis SRANDMEMBER)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.setpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.SetPop(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "SetPop/SetPopAsync",
			Description: "Redis set member pop (StackExchange.Redis SPOP)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.sortedsetrangebyrank",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.SortedSetRangeByRank(?:WithScores)?(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "SortedSetRangeByRank/SortedSetRangeByRankAsync/SortedSetRangeByRankWithScores/SortedSetRangeByRankWithScoresAsync",
			Description: "Redis sorted-set range read by rank (StackExchange.Redis ZRANGE)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.sortedsetrangebyvalue",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.SortedSetRangeByValue(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "SortedSetRangeByValue/SortedSetRangeByValueAsync",
			Description: "Redis sorted-set range read by lex (StackExchange.Redis ZRANGEBYLEX)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.redis.stringgetrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.StringGetRange(?:Async)?\s*\(`,
			ObjectType:  "IDatabase",
			MethodName:  "StringGetRange/StringGetRangeAsync",
			Description: "Redis string substring read (StackExchange.Redis GETRANGE)",
			Assigns:     "return",
		},

		// --- ASP.NET Core cache abstractions (second-order taint) ---
		// IDistributedCache (Microsoft.Extensions.Caching.Distributed) and
		// IMemoryCache (Microsoft.Extensions.Caching.Memory) are the standard
		// .NET caching interfaces, injected via DI and conventionally named
		// `_cache` / `cache` / `_distributedCache` / `_memoryCache`. Reads return
		// previously-stored values that may carry user-controlled taint written
		// on an earlier request. Sync and async read methods are packed into
		// MethodName so tsflow registers all variants. The cache-receiver name
		// match is handled in tsflow matcher.go (parallel to the database case).
		{
			ID:          "csharp.idistributedcache.read",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetString(?:Async)?\s*\(|\.Get(?:Async)?\s*\(`,
			ObjectType:  "IDistributedCache",
			MethodName:  "Get/GetAsync/GetString/GetStringAsync",
			Description: "ASP.NET Core IDistributedCache read (previously-stored, possibly tainted data)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.imemorycache.read",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.Get\s*\(|\.GetOrCreate(?:Async)?\s*\(`,
			ObjectType:  "IMemoryCache",
			MethodName:  "Get/GetOrCreate/GetOrCreateAsync",
			Description: "ASP.NET Core IMemoryCache read (previously-stored, possibly tainted data)",
			Assigns:     "return",
		},

		// --- AWS SQS (.NET SDK) ---
		{
			ID:          "csharp.aws.sqs.receivemessage",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReceiveMessageAsync\s*\(|AmazonSQSClient.*\.ReceiveMessage\s*\(`,
			ObjectType:  "",
			MethodName:  "ReceiveMessageAsync",
			Description: "AWS SQS message reception (untrusted queue data)",
			Assigns:     "return",
		},

		// --- GraphQL resolver sources (HotChocolate IResolverContext) ---
		// HotChocolate is the dominant .NET GraphQL server. Resolver methods
		// receive an IResolverContext (typically named `context` / `ctx`) that
		// exposes caller-controlled query arguments and parent resolver values.
		{
			ID:          "csharp.hotchocolate.argumentvalue",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.ArgumentValue\s*<`,
			ObjectType:  "IResolverContext",
			MethodName:  "ArgumentValue",
			Description: "HotChocolate IResolverContext.ArgumentValue<T>(name) — GraphQL resolver argument from query",
			Assigns:     "return",
		},
		{
			ID:          "csharp.hotchocolate.argumentliteral",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.ArgumentLiteral\s*<`,
			ObjectType:  "IResolverContext",
			MethodName:  "ArgumentLiteral",
			Description: "HotChocolate IResolverContext.ArgumentLiteral<T>(name) — GraphQL resolver argument literal",
			Assigns:     "return",
		},
		{
			ID:          "csharp.hotchocolate.argumentoptional",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.ArgumentOptional\s*<`,
			ObjectType:  "IResolverContext",
			MethodName:  "ArgumentOptional",
			Description: "HotChocolate IResolverContext.ArgumentOptional<T>(name) — optional GraphQL resolver argument",
			Assigns:     "return",
		},
		{
			ID:          "csharp.hotchocolate.parent",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.Parent\s*<`,
			ObjectType:  "IResolverContext",
			MethodName:  "Parent",
			Description: "HotChocolate IResolverContext.Parent<T>() — parent resolver value (may carry prior query input)",
			Assigns:     "return",
		},

		// --- GraphQL resolver sources (GraphQL.NET IResolveFieldContext) ---
		// GraphQL.NET (graphql-dotnet) is the long-standing alternative .NET
		// GraphQL server. Resolver delegates receive an IResolveFieldContext
		// exposing GetArgument<T>(name) and related accessors.
		{
			ID:          "csharp.graphqlnet.getargument",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetArgument\s*<`,
			ObjectType:  "IResolveFieldContext",
			MethodName:  "GetArgument",
			Description: "GraphQL.NET IResolveFieldContext.GetArgument<T>(name) — GraphQL resolver argument from query",
			Assigns:     "return",
		},

		// --- MQTTnet — MQTT broker / client message receive ---
		// MQTTnet is the de-facto C# MQTT library. Inbound MqttApplicationMessage
		// instances are publisher-controlled: payload bytes, topic strings, and
		// converted-string accessors all carry untrusted broker traffic. Used
		// extensively in IoT, telemetry, and inter-service eventing.
		{
			ID:          "csharp.mqttnet.applicationmessage.payloadsegment",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ApplicationMessage\.PayloadSegment`,
			ObjectType:  "ApplicationMessage",
			MethodName:  "PayloadSegment",
			Description: "MQTTnet MqttApplicationMessage.PayloadSegment — raw publisher-controlled MQTT payload (ArraySegment<byte>)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.mqttnet.applicationmessage.payload",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ApplicationMessage\.Payload\b`,
			ObjectType:  "ApplicationMessage",
			MethodName:  "Payload",
			Description: "MQTTnet MqttApplicationMessage.Payload — raw publisher-controlled MQTT payload (byte[], legacy API)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.mqttnet.applicationmessage.converttostring",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ApplicationMessage\.ConvertPayloadToString\s*\(`,
			ObjectType:  "ApplicationMessage",
			MethodName:  "ConvertPayloadToString",
			Description: "MQTTnet MqttApplicationMessage.ConvertPayloadToString() — decoded publisher-controlled MQTT payload",
			Assigns:     "return",
		},
		{
			ID:          "csharp.mqttnet.applicationmessage.topic",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `ApplicationMessage\.Topic\b`,
			ObjectType:  "ApplicationMessage",
			MethodName:  "Topic",
			Description: "MQTTnet MqttApplicationMessage.Topic — publisher-controlled MQTT topic string",
			Assigns:     "return",
		},

		// --- NetMQ — .NET ZeroMQ socket receive ---
		// NetMQ is the canonical C# port of ZeroMQ. Sockets receive frames
		// directly from peers across a network or IPC trust boundary; ZeroMQ
		// has no built-in authentication absent CurveZMQ, so any received
		// frame is untrusted input. Method names (ReceiveFrameString,
		// ReceiveFrameBytes, ReceiveMultipartMessage, ReceiveMultipartStrings)
		// are unique to NetMQ and unambiguous when matched without ObjectType.
		{
			ID:          "csharp.netmq.receiveframestring",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReceiveFrameString\s*\(`,
			ObjectType:  "",
			MethodName:  "ReceiveFrameString",
			Description: "NetMQ socket.ReceiveFrameString() — single ZeroMQ frame from untrusted peer",
			Assigns:     "return",
		},
		{
			ID:          "csharp.netmq.receiveframebytes",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReceiveFrameBytes\s*\(`,
			ObjectType:  "",
			MethodName:  "ReceiveFrameBytes",
			Description: "NetMQ socket.ReceiveFrameBytes() — single ZeroMQ frame bytes from untrusted peer",
			Assigns:     "return",
		},
		{
			ID:          "csharp.netmq.receivemultipartmessage",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReceiveMultipartMessage\s*\(`,
			ObjectType:  "",
			MethodName:  "ReceiveMultipartMessage",
			Description: "NetMQ socket.ReceiveMultipartMessage() — multi-frame ZeroMQ message from untrusted peer",
			Assigns:     "return",
		},
		{
			ID:          "csharp.netmq.receivemultipartstrings",
			Category:    taint.SrcExternal,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReceiveMultipartStrings\s*\(`,
			ObjectType:  "",
			MethodName:  "ReceiveMultipartStrings",
			Description: "NetMQ socket.ReceiveMultipartStrings() — list of ZeroMQ frame strings from untrusted peer",
			Assigns:     "return",
		},

		// --- NoSQL document-database read sources (second-order injection) ---
		// Documents fetched back out of a document store carry taint from
		// whatever earlier request wrote them. Mirrors the existing Dapper /
		// EF Core / StackExchange.Redis second-order sources, and the Java
		// MongoDB and Python pymongo/SQLAlchemy read-source additions.
		{
			ID:          "csharp.mongo.findsync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.FindSync\s*\(`,
			ObjectType:  "",
			MethodName:  "FindSync",
			Description: "MongoDB.Driver IMongoCollection.FindSync — synchronous cursor over stored documents (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.cosmos.container.readitemasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReadItemAsync\s*<`,
			ObjectType:  "",
			MethodName:  "ReadItemAsync",
			Description: "Azure Cosmos DB Container.ReadItemAsync — point read returning a stored document (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.cosmos.container.readitemstreamasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReadItemStreamAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "ReadItemStreamAsync",
			Description: "Azure Cosmos DB Container.ReadItemStreamAsync — stream-mode point read of a stored document (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.cosmos.feediterator.readnextasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReadNextAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "ReadNextAsync",
			Description: "Azure Cosmos DB FeedIterator.ReadNextAsync — next page of stored documents from a query iterator (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.cosmos.documentclient.readdocumentasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.ReadDocumentAsync\s*\(`,
			ObjectType:  "",
			MethodName:  "ReadDocumentAsync",
			Description: "Azure Cosmos DB DocumentClient.ReadDocumentAsync (legacy SDK v2) — reads a stored document (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.ravendb.session.load",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.Load<|\.LoadAsync<`,
			ObjectType:  "IDocumentSession",
			MethodName:  "Load/LoadAsync",
			Description: "RavenDB IDocumentSession.Load / IAsyncDocumentSession.LoadAsync — loads a stored document by id (second-order injection source; also matches NHibernate ISession.Load)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.ravendb.session.query",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.Query<`,
			ObjectType:  "IDocumentSession",
			MethodName:  "Query",
			Description: "RavenDB IDocumentSession.Query — LINQ query over stored documents (second-order injection source; also matches NHibernate ISession.Query)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.ravendb.session.documentquery",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.DocumentQuery\s*<`,
			ObjectType:  "",
			MethodName:  "DocumentQuery",
			Description: "RavenDB IDocumentSession.Advanced.DocumentQuery — low-level query over stored documents (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.litedb.collection.findbyid",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.FindById\s*\(`,
			ObjectType:  "",
			MethodName:  "FindById",
			Description: "LiteDB ILiteCollection.FindById — reads a stored document by id (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.litedb.collection.findone",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `\.FindOne\s*\(`,
			ObjectType:  "",
			MethodName:  "FindOne",
			Description: "LiteDB ILiteCollection.FindOne — reads the first stored document matching a predicate (second-order injection source)",
			Assigns:     "return",
		},

		// --- DataStax CassandraCSharpDriver second-order read sources ---
		// Rows read back from Cassandra carry taint from whatever earlier write
		// stored them. ISession.Execute / ExecuteAsync return a RowSet, and
		// Row.GetValue<T>(name|index) extracts a stored column value. The same
		// ISession.Execute call is also a CQL-injection sink (see
		// csharp.cassandra.session.execute in csharp_sinks.go) when its CQL
		// argument is tainted — these source entries cover the read direction.
		// Reference: https://docs.datastax.com/en/latest-csharp-driver-api/api/Cassandra.Row.html
		{
			ID:          "csharp.cassandra.session.execute",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:session|sess|cqlSession|cassandraSession|cassSession)\.Execute\s*\(`,
			ObjectType:  "Session",
			MethodName:  "Execute",
			Description: "DataStax CassandraCSharpDriver ISession.Execute — RowSet of previously-stored rows (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.cassandra.session.executeasync",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:session|sess|cqlSession|cassandraSession|cassSession)\.ExecuteAsync\s*\(`,
			ObjectType:  "Session",
			MethodName:  "ExecuteAsync",
			Description: "DataStax CassandraCSharpDriver ISession.ExecuteAsync — awaited RowSet of previously-stored rows (second-order injection source)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.cassandra.row.getvalue",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCSharp,
			Pattern:     `(?:row|r)\.GetValue\s*[<(]`,
			ObjectType:  "Row",
			MethodName:  "GetValue",
			Description: "DataStax CassandraCSharpDriver Row.GetValue<T>(name|index) — reads a stored column value from a Cassandra result row (second-order injection source)",
			Assigns:     "return",
		},

		// =================================================================
		// Mined from public MIT-licensed security-model data.
		// =================================================================

		{ID: "csharp.apigatewayevents.apigatewayhttpapiv2proxyrequest.get_headers", Category: taint.SrcExternal, Pattern: `\.get_Headers\s*\(`, ObjectType: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest", MethodName: "get_Headers", Description: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Headers — remote source", Assigns: "return"},
		{ID: "csharp.apigatewayevents.apigatewayhttpapiv2proxyrequest.get_body", Category: taint.SrcExternal, Pattern: `\.get_Body\s*\(`, ObjectType: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest", MethodName: "get_Body", Description: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Body — remote source", Assigns: "return"},
		{ID: "csharp.apigatewayevents.apigatewayhttpapiv2proxyrequest.get_rawpath", Category: taint.SrcExternal, Pattern: `\.get_RawPath\s*\(`, ObjectType: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest", MethodName: "get_RawPath", Description: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawPath — remote source", Assigns: "return"},
		{ID: "csharp.apigatewayevents.apigatewayhttpapiv2proxyrequest.get_rawquerystring", Category: taint.SrcExternal, Pattern: `\.get_RawQueryString\s*\(`, ObjectType: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest", MethodName: "get_RawQueryString", Description: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_RawQueryString — remote source", Assigns: "return"},
		{ID: "csharp.apigatewayevents.apigatewayhttpapiv2proxyrequest.get_cookies", Category: taint.SrcExternal, Pattern: `\.get_Cookies\s*\(`, ObjectType: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest", MethodName: "get_Cookies", Description: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_Cookies — remote source", Assigns: "return"},
		{ID: "csharp.apigatewayevents.apigatewayhttpapiv2proxyrequest.get_pathparameters", Category: taint.SrcExternal, Pattern: `\.get_PathParameters\s*\(`, ObjectType: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest", MethodName: "get_PathParameters", Description: "Amazon.Lambda.APIGatewayEvents.APIGatewayHttpApiV2ProxyRequest.get_PathParameters — remote source", Assigns: "return"},
		{ID: "csharp.dapper.sqlmapper.queryfirstordefault", Category: taint.SrcDatabase, Pattern: `\.QueryFirstOrDefault\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryFirstOrDefault", Description: "Dapper.SqlMapper.QueryFirstOrDefault — database source", Assigns: "return"},
		{ID: "csharp.dapper.sqlmapper.queryfirstordefaultasync", Category: taint.SrcDatabase, Pattern: `\.QueryFirstOrDefaultAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QueryFirstOrDefaultAsync", Description: "Dapper.SqlMapper.QueryFirstOrDefaultAsync — database source", Assigns: "return"},
		{ID: "csharp.dapper.sqlmapper.querysingleordefault", Category: taint.SrcDatabase, Pattern: `\.QuerySingleOrDefault\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QuerySingleOrDefault", Description: "Dapper.SqlMapper.QuerySingleOrDefault — database source", Assigns: "return"},
		{ID: "csharp.dapper.sqlmapper.querysingleordefaultasync", Category: taint.SrcDatabase, Pattern: `\.QuerySingleOrDefaultAsync\s*\(`, ObjectType: "Dapper.SqlMapper", MethodName: "QuerySingleOrDefaultAsync", Description: "Dapper.SqlMapper.QuerySingleOrDefaultAsync — database source", Assigns: "return"},
		{ID: "csharp.components.navigationmanager.get_baseuri", Category: taint.SrcExternal, Pattern: `\.get_BaseUri\s*\(`, ObjectType: "Microsoft.AspNetCore.Components.NavigationManager", MethodName: "get_BaseUri", Description: "Microsoft.AspNetCore.Components.NavigationManager.get_BaseUri — remote source", Assigns: "return"},
		{ID: "csharp.components.navigationmanager.get_uri", Category: taint.SrcExternal, Pattern: `\.get_Uri\s*\(`, ObjectType: "Microsoft.AspNetCore.Components.NavigationManager", MethodName: "get_Uri", Description: "Microsoft.AspNetCore.Components.NavigationManager.get_Uri — remote source", Assigns: "return"},
		{ID: "csharp.components.supplyparameterfromformattribute.", Category: taint.SrcExternal, Pattern: `\[SupplyParameterFromForm\]`, ObjectType: "Microsoft.AspNetCore.Components.SupplyParameterFromFormAttribute", MethodName: "", Description: "Microsoft.AspNetCore.Components.SupplyParameterFromFormAttribute. — remote source", Assigns: "return"},
		{ID: "csharp.components.supplyparameterfromqueryattribute.", Category: taint.SrcExternal, Pattern: `\[SupplyParameterFromQuery\]`, ObjectType: "Microsoft.AspNetCore.Components.SupplyParameterFromQueryAttribute", MethodName: "", Description: "Microsoft.AspNetCore.Components.SupplyParameterFromQueryAttribute. — remote source", Assigns: "return"},
		{ID: "csharp.sockets.updclient.endreceive", Category: taint.SrcExternal, Pattern: `\.EndReceive\s*\(`, ObjectType: "System.Net.Sockets.UpdClient", MethodName: "EndReceive", Description: "System.Net.Sockets.UpdClient.EndReceive — remote source", Assigns: "return"},
		{ID: "csharp.sockets.updclient.receive", Category: taint.SrcExternal, Pattern: `(?:[uU]dp\w*|UdpClient)\.Receive\s*\(`, ObjectType: "System.Net.Sockets.UpdClient", MethodName: "Receive", Description: "System.Net.Sockets.UpdClient.Receive — remote source", Assigns: "return"},

		// --- Additional ASP.NET Core / Web API request sources ---
		{ID: "csharp.aspnetcore.httprequest.querystring_get", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.QueryString\b`, ObjectType: "Microsoft.AspNetCore.Http.HttpRequest", MethodName: "QueryString", Description: "ASP.NET Core HttpRequest.QueryString — raw query string", Assigns: "return"},
		{ID: "csharp.aspnetcore.httprequest.routevalues", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.RouteValues\b`, ObjectType: "Microsoft.AspNetCore.Http.HttpRequest", MethodName: "RouteValues", Description: "ASP.NET Core HttpRequest.RouteValues — route-bound parameters", Assigns: "return"},
		{ID: "csharp.aspnetcore.httprequest.scheme_host", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.Scheme\b|\.Host\b|\.PathBase\b`, ObjectType: "Microsoft.AspNetCore.Http.HttpRequest", MethodName: "Scheme/Host/PathBase", Description: "ASP.NET Core HttpRequest.Scheme/Host/PathBase — URL components (host can be spoofed via Host header)", Assigns: "return"},
		{ID: "csharp.aspnetcore.httprequest.contenttype", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.ContentType\b|\.ContentLength\b`, ObjectType: "Microsoft.AspNetCore.Http.HttpRequest", MethodName: "ContentType/ContentLength", Description: "ASP.NET Core HttpRequest.ContentType / ContentLength — client-supplied content headers", Assigns: "return"},
		{ID: "csharp.aspnetcore.httpcontext.user", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.User\b`, ObjectType: "Microsoft.AspNetCore.Http.HttpContext", MethodName: "User", Description: "ASP.NET Core HttpContext.User — ClaimsPrincipal (claims may be attacker-influenced)", Assigns: "return"},
		{ID: "csharp.aspnetcore.httpcontext.connection_remote", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.Connection\.RemoteIpAddress\b`, ObjectType: "Microsoft.AspNetCore.Http.HttpContext", MethodName: "Connection.RemoteIpAddress", Description: "ASP.NET Core HttpContext.Connection.RemoteIpAddress — client IP (spoofable via X-Forwarded-For)", Assigns: "return"},
		{ID: "csharp.aspnetcore.iformcollection", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `IFormCollection\b`, ObjectType: "Microsoft.AspNetCore.Http.IFormCollection", MethodName: "IFormCollection", Description: "ASP.NET Core IFormCollection — form-encoded request fields", Assigns: "return"},
		{ID: "csharp.aspnetcore.iformfile.filename", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\.FileName\b`, ObjectType: "Microsoft.AspNetCore.Http.IFormFile", MethodName: "FileName", Description: "ASP.NET Core IFormFile.FileName — client-supplied upload filename", Assigns: "return"},

		// MVC binding attributes — the parameter ANNOTATED is the source
		{ID: "csharp.aspnetcore.mvc.fromquery", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\[FromQuery\]`, ObjectType: "Microsoft.AspNetCore.Mvc", MethodName: "FromQuery", Description: "[FromQuery] attribute — binds a controller parameter to a query-string value", Assigns: "return"},
		{ID: "csharp.aspnetcore.mvc.fromroute", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\[FromRoute\]`, ObjectType: "Microsoft.AspNetCore.Mvc", MethodName: "FromRoute", Description: "[FromRoute] attribute — binds a controller parameter to a route value", Assigns: "return"},
		{ID: "csharp.aspnetcore.mvc.frombody", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\[FromBody\]`, ObjectType: "Microsoft.AspNetCore.Mvc", MethodName: "FromBody", Description: "[FromBody] attribute — binds a controller parameter to the deserialised JSON body", Assigns: "return"},
		{ID: "csharp.aspnetcore.mvc.fromheader", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\[FromHeader\]`, ObjectType: "Microsoft.AspNetCore.Mvc", MethodName: "FromHeader", Description: "[FromHeader] attribute — binds a controller parameter to a request header", Assigns: "return"},
		{ID: "csharp.aspnetcore.mvc.fromform", Category: taint.SrcUserInput, Language: rules.LangCSharp, Pattern: `\[FromForm\]`, ObjectType: "Microsoft.AspNetCore.Mvc", MethodName: "FromForm", Description: "[FromForm] attribute — binds a controller parameter to a form field", Assigns: "return"},

		// --- ServiceStack: IRequest untrusted-input accessors ---
		// ServiceStack services reach raw client input through the injected
		// IRequest (base.Request inside a Service, or an IRequest filter
		// argument). These convenience accessors return attacker-controlled
		// strings — GetParam() searches QueryString -> FormData -> Cookies ->
		// Items, so any value it returns originates from the client. The ASP.NET
		// Core HttpRequest sources above don't cover ServiceStack's own IRequest
		// API surface (different method names: GetParam, GetQueryStringOrForm,
		// PathInfo, RawUrl, Items). ObjectType "ServiceStack.Web.IRequest"
		// contains "request" so the request-receiver heuristic associates
		// base.Request / req / Request receivers.
		{
			ID:          "csharp.servicestack.irequest.getparam",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetParam\s*\(`,
			ObjectType:  "ServiceStack.Web.IRequest",
			MethodName:  "GetParam",
			Description: "ServiceStack IRequest.GetParam(name) — client value from QueryString/FormData/Cookies/Items (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.servicestack.irequest.getquerystringorform",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetQueryStringOrForm\s*\(`,
			ObjectType:  "ServiceStack.Web.IRequest",
			MethodName:  "GetQueryStringOrForm",
			Description: "ServiceStack IRequest.GetQueryStringOrForm(name) — client value from query string or form data (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.servicestack.irequest.pathinfo",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.PathInfo\b|\.RawUrl\b|\.AbsoluteUri\b`,
			ObjectType:  "ServiceStack.Web.IRequest",
			MethodName:  "PathInfo/RawUrl/AbsoluteUri",
			Description: "ServiceStack IRequest.PathInfo/RawUrl/AbsoluteUri — client-controlled URL components (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.servicestack.irequest.items",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.GetItem\s*\(|\.QueryString\.Get\s*\(|\.FormData\.Get\s*\(`,
			ObjectType:  "ServiceStack.Web.IRequest",
			MethodName:  "GetItem/QueryString.Get/FormData.Get",
			Description: "ServiceStack IRequest.GetItem(key) / QueryString.Get / FormData.Get — client request data (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "csharp.servicestack.irequiresrequeststream.requeststream",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCSharp,
			Pattern:     `\.RequestStream\b|\.GetRawBody\s*\(`,
			ObjectType:  "ServiceStack.Web.IRequest",
			MethodName:  "RequestStream/GetRawBody",
			Description: "ServiceStack IRequiresRequestStream.RequestStream / IRequest.GetRawBody() — raw unparsed request body (untrusted)",
			Assigns:     "return",
		},
	}
}
