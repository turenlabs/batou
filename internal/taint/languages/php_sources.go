package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (phpCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// Superglobals
		{ID: "php.superglobal.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_GET\s*\[`, ObjectType: "", MethodName: "$_GET", Description: "PHP $_GET superglobal", Assigns: "return"},
		{ID: "php.superglobal.post", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_POST\s*\[`, ObjectType: "", MethodName: "$_POST", Description: "PHP $_POST superglobal", Assigns: "return"},
		{ID: "php.superglobal.request", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_REQUEST\s*\[`, ObjectType: "", MethodName: "$_REQUEST", Description: "PHP $_REQUEST superglobal", Assigns: "return"},
		{ID: "php.superglobal.files", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_FILES\s*\[`, ObjectType: "", MethodName: "$_FILES", Description: "PHP $_FILES superglobal", Assigns: "return"},
		{ID: "php.superglobal.cookie", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_COOKIE\s*\[`, ObjectType: "", MethodName: "$_COOKIE", Description: "PHP $_COOKIE superglobal", Assigns: "return"},
		{ID: "php.superglobal.server.http", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_SERVER\s*\[\s*['"]HTTP_`, ObjectType: "", MethodName: "$_SERVER[HTTP_]", Description: "PHP $_SERVER HTTP headers", Assigns: "return"},
		{ID: "php.superglobal.server.request_uri", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_SERVER\s*\[\s*['"]REQUEST_URI['"]\s*\]`, ObjectType: "", MethodName: "$_SERVER[REQUEST_URI]", Description: "PHP $_SERVER REQUEST_URI", Assigns: "return"},
		{ID: "php.superglobal.server.query_string", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$_SERVER\s*\[\s*['"]QUERY_STRING['"]\s*\]`, ObjectType: "", MethodName: "$_SERVER[QUERY_STRING]", Description: "PHP $_SERVER QUERY_STRING", Assigns: "return"},
		{ID: "php.input.stream", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `file_get_contents\s*\(\s*['"]php://input['"]\s*\)`, ObjectType: "", MethodName: "file_get_contents(php://input)", Description: "PHP raw input stream", Assigns: "return"},

		// Environment
		{ID: "php.superglobal.env", Category: taint.SrcEnvVar, Language: rules.LangPHP, Pattern: `\$_ENV\s*\[`, ObjectType: "", MethodName: "$_ENV", Description: "PHP $_ENV superglobal", Assigns: "return"},
		{ID: "php.getenv", Category: taint.SrcEnvVar, Language: rules.LangPHP, Pattern: `\bgetenv\s*\(`, ObjectType: "", MethodName: "getenv", Description: "PHP getenv() function", Assigns: "return"},

		// CLI
		{ID: "php.argv", Category: taint.SrcCLIArg, Language: rules.LangPHP, Pattern: `\$argv`, ObjectType: "", MethodName: "$argv", Description: "PHP CLI arguments", Assigns: "return"},
		{ID: "php.stdin.fgets", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `fgets\s*\(\s*STDIN\s*\)`, ObjectType: "", MethodName: "fgets(STDIN)", Description: "Standard input read", Assigns: "return"},

		// File sources
		{ID: "php.fread", Category: taint.SrcFileRead, Language: rules.LangPHP, Pattern: `\bfread\s*\(`, ObjectType: "", MethodName: "fread", Description: "File read via fread()", Assigns: "return"},
		{ID: "php.file_get_contents", Category: taint.SrcFileRead, Language: rules.LangPHP, Pattern: `\bfile_get_contents\s*\(`, ObjectType: "", MethodName: "file_get_contents", Description: "File read via file_get_contents()", Assigns: "return"},

		// Laravel framework sources
		{ID: "php.laravel.request.input", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->input\s*\(`, ObjectType: "Request", MethodName: "input", Description: "Laravel Request::input() user data", Assigns: "return"},
		{ID: "php.laravel.request.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->get\s*\(`, ObjectType: "Request", MethodName: "get", Description: "Laravel Request::get() user data", Assigns: "return"},
		{ID: "php.laravel.request.all", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->all\s*\(`, ObjectType: "Request", MethodName: "all", Description: "Laravel Request::all() user data", Assigns: "return"},
		{ID: "php.laravel.request.query", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->query\s*\(`, ObjectType: "Request", MethodName: "query", Description: "Laravel Request::query() user data", Assigns: "return"},
		{ID: "php.laravel.request.static.input", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `Request::input\s*\(`, ObjectType: "Request", MethodName: "Request::input", Description: "Laravel static Request::input()", Assigns: "return"},
		{ID: "php.laravel.route.current", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `Route::current\s*\(`, ObjectType: "Route", MethodName: "Route::current", Description: "Laravel Route::current() route data", Assigns: "return"},
		{ID: "php.laravel.route.parameter", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->route\s*\(`, ObjectType: "Request", MethodName: "route", Description: "Laravel route parameter data", Assigns: "return"},

		// Symfony framework sources
		{ID: "php.symfony.request.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->get\s*\(`, ObjectType: "SymfonyRequest", MethodName: "get", Description: "Symfony Request::get() user data", Assigns: "return"},
		{ID: "php.symfony.request.query.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->query->get\s*\(`, ObjectType: "ParameterBag", MethodName: "query->get", Description: "Symfony query parameter bag", Assigns: "return"},
		{ID: "php.symfony.request.request.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->request->get\s*\(`, ObjectType: "ParameterBag", MethodName: "request->get", Description: "Symfony POST parameter bag", Assigns: "return"},

		// CodeIgniter framework sources
		{ID: "php.codeigniter.input.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$this->input->get\s*\(`, ObjectType: "CI_Input", MethodName: "get", Description: "CodeIgniter input->get() user data", Assigns: "return"},
		{ID: "php.codeigniter.input.post", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$this->input->post\s*\(`, ObjectType: "CI_Input", MethodName: "post", Description: "CodeIgniter input->post() user data", Assigns: "return"},
		{ID: "php.codeigniter.input.cookie", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$this->input->cookie\s*\(`, ObjectType: "CI_Input", MethodName: "cookie", Description: "CodeIgniter input->cookie() user data", Assigns: "return"},

		// WordPress sources
		{ID: "php.wordpress.get_option", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\bget_option\s*\(`, ObjectType: "", MethodName: "get_option", Description: "WordPress get_option() database value", Assigns: "return"},
		{ID: "php.wordpress.get_post_meta", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\bget_post_meta\s*\(`, ObjectType: "", MethodName: "get_post_meta", Description: "WordPress get_post_meta() database value", Assigns: "return"},
		{ID: "php.wordpress.get_user_meta", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\bget_user_meta\s*\(`, ObjectType: "", MethodName: "get_user_meta", Description: "WordPress get_user_meta() database value", Assigns: "return"},

		// Session fixation source
		{ID: "php.session_id.source", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\bsession_id\s*\(`, ObjectType: "", MethodName: "session_id", Description: "session_id() can read attacker-controlled session ID", Assigns: "return"},

		// AWS Lambda event source (Bref PHP runtime)
		{ID: "php.aws.lambda.event", Category: taint.SrcExternal, Language: rules.LangPHP, Pattern: `function\s*\(\s*\$event\s*\)|\$event\s*\[`, ObjectType: "bref/lambda", MethodName: "Lambda handler event", Description: "AWS Lambda event data via Bref PHP runtime", Assigns: "return"},
		// AWS SQS message source
		{ID: "php.aws.sqs.receive", Category: taint.SrcExternal, Language: rules.LangPHP, Pattern: `->receiveMessage\s*\(`, ObjectType: "Aws\\Sqs\\SqsClient", MethodName: "receiveMessage", Description: "AWS SQS message data from queue", Assigns: "return"},
		// AWS S3 object source
		{ID: "php.aws.s3.getobject", Category: taint.SrcExternal, Language: rules.LangPHP, Pattern: `->getObject\s*\(`, ObjectType: "Aws\\S3\\S3Client", MethodName: "getObject", Description: "AWS S3 object data from potentially untrusted bucket", Assigns: "return"},
		// GCP Pub/Sub source
		{ID: "php.gcp.pubsub.pull", Category: taint.SrcExternal, Language: rules.LangPHP, Pattern: `->pull\s*\(`, ObjectType: "Google\\Cloud\\PubSub", MethodName: "pull", Description: "GCP Pub/Sub message data", Assigns: "return"},

		// --- Additional superglobals ---
		{
			ID:          "php.superglobal.server.remote_addr",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$_SERVER\s*\[\s*['"]REMOTE_ADDR['"]`,
			ObjectType:  "",
			MethodName:  "$_SERVER[REMOTE_ADDR]",
			Description: "Client IP address (spoofable via proxy headers)",
			Assigns:     "return",
		},
		{
			ID:          "php.superglobal.server.http_x_forwarded",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$_SERVER\s*\[\s*['"]HTTP_X_FORWARDED`,
			ObjectType:  "",
			MethodName:  "$_SERVER[HTTP_X_FORWARDED_*]",
			Description: "X-Forwarded-* proxy headers (client-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "php.getallheaders",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `getallheaders\s*\(|apache_request_headers\s*\(`,
			ObjectType:  "",
			MethodName:  "getallheaders/apache_request_headers",
			Description: "All HTTP request headers",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.request.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$request->header\s*\(|request\(\)->header\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "header",
			Description: "Laravel request header value",
			Assigns:     "return",
		},
	}
}
