package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (c *GoCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- Standard library: net/http ---
		{
			ID:          "go.http.request.formvalue",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `\.FormValue\(`,
			ObjectType:  "*http.Request",
			MethodName:  "FormValue",
			Description: "HTTP form parameter",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.url.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `\.URL\.Query\(\)`,
			ObjectType:  "*http.Request",
			MethodName:  "URL.Query",
			Description: "URL query parameters",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.Body|request\.Body`,
			ObjectType:  "*http.Request",
			MethodName:  "Body",
			Description: "HTTP request body",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.Header\.Get\(`,
			ObjectType:  "*http.Request",
			MethodName:  "Header.Get",
			Description: "HTTP request header",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.Cookie\(`,
			ObjectType:  "*http.Request",
			MethodName:  "Cookie",
			Description: "HTTP cookie value",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.pathvalue",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.PathValue\(`,
			ObjectType:  "*http.Request",
			MethodName:  "PathValue",
			Description: "URL path parameter (Go 1.22+)",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.postform",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.PostFormValue\(`,
			ObjectType:  "*http.Request",
			MethodName:  "PostFormValue",
			Description: "POST form value",
			Assigns:     "return",
		},
		{
			ID:          "go.http.request.multipart",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.MultipartForm`,
			ObjectType:  "*http.Request",
			MethodName:  "MultipartForm",
			Description: "Multipart form data",
			Assigns:     "return",
		},

		// --- Standard library: os ---
		{
			ID:          "go.os.args",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangGo,
			Pattern:     `os\.Args`,
			ObjectType:  "",
			MethodName:  "os.Args",
			Description: "Command-line arguments",
			Assigns:     "return",
		},
		{
			ID:          "go.os.stdin",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `os\.Stdin`,
			ObjectType:  "",
			MethodName:  "os.Stdin",
			Description: "Standard input",
			Assigns:     "return",
		},
		{
			ID:          "go.os.getenv",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangGo,
			Pattern:     `os\.Getenv\(`,
			ObjectType:  "",
			MethodName:  "Getenv",
			Description: "Environment variable",
			Assigns:     "return",
		},

		// --- Standard library: io ---
		{
			ID:          "go.io.readall",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGo,
			Pattern:     `io\.ReadAll\(`,
			ObjectType:  "",
			MethodName:  "ReadAll",
			Description: "Read all bytes from reader",
			Assigns:     "return",
		},

		// --- Standard library: bufio ---
		{
			ID:          "go.bufio.scanner",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `scanner\.Text\(\)`,
			ObjectType:  "*bufio.Scanner",
			MethodName:  "Text",
			Description: "Scanner text input",
			Assigns:     "return",
		},

		// --- Standard library: net ---
		{
			ID:          "go.net.conn",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGo,
			Pattern:     `conn\.Read\(`,
			ObjectType:  "net.Conn",
			MethodName:  "Read",
			Description: "Network connection read",
			Assigns:     "return",
		},

		// --- Standard library: database/sql ---
		{
			ID:          "go.database.rows",
			Category:    taint.SrcDatabase,
			Language:    rules.LangGo,
			Pattern:     `rows\.Scan\(`,
			ObjectType:  "*sql.Rows",
			MethodName:  "Scan",
			Description: "Database row scan result",
			Assigns:     "return",
		},

		// --- Gin framework ---
		{
			ID:          "go.gin.context",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `c\.Query\(|c\.Param\(|c\.PostForm\(|c\.GetHeader\(`,
			ObjectType:  "*gin.Context",
			MethodName:  "Query/Param/PostForm/GetHeader",
			Description: "Gin framework request input",
			Assigns:     "return",
		},

		// --- Echo framework ---
		{
			ID:          "go.echo.context",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `c\.QueryParam\(|c\.Param\(|c\.FormValue\(`,
			ObjectType:  "echo.Context",
			MethodName:  "QueryParam/Param/FormValue",
			Description: "Echo framework request input",
			Assigns:     "return",
		},

		// --- Fiber framework ---
		{
			ID:          "go.fiber.context",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `c\.Query\(|c\.Params\(|c\.Body\(`,
			ObjectType:  "*fiber.Ctx",
			MethodName:  "Query/Params/Body",
			Description: "Fiber framework request input",
			Assigns:     "return",
		},

		// --- gRPC ---
		{
			ID:          "go.grpc.metadata",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `metadata\.FromIncomingContext\(`,
			ObjectType:  "",
			MethodName:  "FromIncomingContext",
			Description: "gRPC incoming request metadata",
			Assigns:     "return",
		},
		{
			ID:          "go.grpc.stream.recv",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGo,
			Pattern:     `\.Recv\(`,
			ObjectType:  "grpc.ServerStream",
			MethodName:  "Recv",
			Description: "gRPC server stream receive",
			Assigns:     "return",
		},

		// --- gorilla/mux ---
		{
			ID:          "go.gorilla.mux.vars",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `mux\.Vars\(`,
			ObjectType:  "",
			MethodName:  "Vars",
			Description: "gorilla/mux URL route variables",
			Assigns:     "return",
		},

		// --- chi router ---
		{
			ID:          "go.chi.urlparam",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `chi\.URLParam\(`,
			ObjectType:  "",
			MethodName:  "URLParam",
			Description: "chi router URL parameter",
			Assigns:     "return",
		},

		// --- Beego framework ---
		{
			ID:          "go.beego.controller.input",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `\.GetString\(|\.GetStrings\(|\.Input\(\)`,
			ObjectType:  "*beego.Controller",
			MethodName:  "GetString/GetStrings/Input",
			Description: "Beego controller request input",
			Assigns:     "return",
		},

		// --- encoding/json Decoder ---
		{
			ID:          "go.json.newdecoder",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangGo,
			Pattern:     `json\.NewDecoder\(`,
			ObjectType:  "",
			MethodName:  "NewDecoder",
			Description: "JSON decoder from untrusted reader",
			Assigns:     "return",
		},

		// --- Cloud SDK: AWS Lambda ---
		{
			ID:          "go.aws.lambda.event",
			Category:    taint.SrcExternal,
			Language:    rules.LangGo,
			Pattern:     `func\s+\w+\(\s*ctx\s+context\.Context\s*,\s*\w+\s+events\.\w+Event`,
			ObjectType:  "aws-lambda-go",
			MethodName:  "Lambda handler event",
			Description: "AWS Lambda event data from external trigger",
			Assigns:     "return",
		},
		// --- Cloud SDK: AWS SQS ---
		{
			ID:          "go.aws.sqs.receive",
			Category:    taint.SrcExternal,
			Language:    rules.LangGo,
			Pattern:     `sqs\.ReceiveMessage\(|\.ReceiveMessage\(`,
			ObjectType:  "sqs.Client",
			MethodName:  "ReceiveMessage",
			Description: "AWS SQS message data from queue",
			Assigns:     "return",
		},
		// --- Cloud SDK: AWS S3 ---
		{
			ID:          "go.aws.s3.getobject",
			Category:    taint.SrcExternal,
			Language:    rules.LangGo,
			Pattern:     `s3\.GetObject\(|\.GetObject\(`,
			ObjectType:  "s3.Client",
			MethodName:  "GetObject",
			Description: "AWS S3 object data from potentially untrusted bucket",
			Assigns:     "return",
		},
		// --- Cloud SDK: GCP Cloud Functions ---
		{
			ID:          "go.gcp.cloudfunctions.event",
			Category:    taint.SrcExternal,
			Language:    rules.LangGo,
			Pattern:     `func\s+\w+\(\s*ctx\s+context\.Context\s*,\s*e\s+`,
			ObjectType:  "cloud.google.com/go/functions",
			MethodName:  "Cloud Function event",
			Description: "GCP Cloud Functions event data from external trigger",
			Assigns:     "return",
		},
		// --- Cloud SDK: GCP Pub/Sub ---
		{
			ID:          "go.gcp.pubsub.receive",
			Category:    taint.SrcExternal,
			Language:    rules.LangGo,
			Pattern:     `sub\.Receive\(|\.Receive\(\s*ctx`,
			ObjectType:  "pubsub.Subscription",
			MethodName:  "Receive",
			Description: "GCP Pub/Sub message data",
			Assigns:     "return",
		},

		// --- Standard library: os (file read) ---
		{
			ID:          "go.os.readfile",
			Category:    taint.SrcFileRead,
			Language:    rules.LangGo,
			Pattern:     `os\.ReadFile\(`,
			ObjectType:  "",
			MethodName:  "ReadFile",
			Description: "File contents from os.ReadFile",
			Assigns:     "return",
		},

		// --- Standard library: net (dial) ---
		{
			ID:          "go.net.dial",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGo,
			Pattern:     `net\.Dial\(`,
			ObjectType:  "",
			MethodName:  "Dial",
			Description: "Network connection dial",
			Assigns:     "return",
		},

		// --- gorilla/websocket ---
		{
			ID:          "go.gorilla.websocket.readmessage",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGo,
			Pattern:     `\.ReadMessage\(`,
			ObjectType:  "*websocket.Conn",
			MethodName:  "ReadMessage",
			Description: "WebSocket message read",
			Assigns:     "return",
		},

		// --- Viper configuration ---
		{
			ID:          "go.viper.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangGo,
			Pattern:     `viper\.Get\w*\(`,
			ObjectType:  "viper",
			MethodName:  "Get*",
			Description: "Viper configuration value (potentially from untrusted config)",
			Assigns:     "return",
		},

		// --- Cobra CLI framework ---
		{
			ID:          "go.cobra.args",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangGo,
			Pattern:     `cobra\.Command.*\.Args|cmd\.Flags\(\)\.GetString\(`,
			ObjectType:  "*cobra.Command",
			MethodName:  "Args/Flags.GetString",
			Description: "Cobra CLI framework arguments",
			Assigns:     "return",
		},

		// --- Standard library: flag ---
		{
			ID:          "go.flag.string",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangGo,
			Pattern:     `flag\.String\(|flag\.StringVar\(`,
			ObjectType:  "",
			MethodName:  "flag.String/StringVar",
			Description: "Flag package CLI string argument",
			Assigns:     "return",
		},

		// --- Standard library: os ---
		{
			ID:          "go.os.lookupenv",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangGo,
			Pattern:     `os\.LookupEnv\(`,
			ObjectType:  "",
			MethodName:  "LookupEnv",
			Description: "Environment variable with existence check",
			Assigns:     "return",
		},

		// --- Standard library: net/http ---
		{
			ID:          "go.http.request.url.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.URL\.Path|request\.URL\.Path`,
			ObjectType:  "*http.Request",
			MethodName:  "URL.Path",
			Description: "Raw URL path from HTTP request",
			Assigns:     "return",
		},

		// --- Standard library: bufio ---
		{
			ID:          "go.bufio.reader.readstring",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `reader\.ReadString\(|bufio\.NewReader\(`,
			ObjectType:  "*bufio.Reader",
			MethodName:  "ReadString",
			Description: "Buffered reader string input",
			Assigns:     "return",
		},

		// --- Standard library: net/http ---
		{
			ID:          "go.http.request.referer",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGo,
			Pattern:     `r\.Referer\(\)|request\.Referer\(\)`,
			ObjectType:  "*http.Request",
			MethodName:  "Referer",
			Description: "HTTP Referer header (user-controlled)",
			Assigns:     "return",
		},
	}
}
