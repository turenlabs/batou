package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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

		// Symfony framework sources — attribute-based (matches $request->query, $request->headers, etc.)
		{ID: "php.symfony.request.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->get\s*\(`, ObjectType: "Request", MethodName: "get", Description: "Symfony Request::get() user data", Assigns: "return"},
		{ID: "php.symfony.request.query", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->query`, ObjectType: "Request", MethodName: "query", Description: "Symfony query parameter bag", Assigns: "return"},
		{ID: "php.symfony.request.request", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->request`, ObjectType: "Request", MethodName: "request", Description: "Symfony POST parameter bag", Assigns: "return"},
		{ID: "php.symfony.request.headers", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->headers`, ObjectType: "Request", MethodName: "headers", Description: "Symfony request headers bag", Assigns: "return"},
		{ID: "php.symfony.request.cookies", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->cookies`, ObjectType: "Request", MethodName: "cookies", Description: "Symfony request cookies bag", Assigns: "return"},
		{ID: "php.symfony.request.getcontent", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->getContent\s*\(`, ObjectType: "Request", MethodName: "getContent", Description: "Symfony raw request body", Assigns: "return"},
		{ID: "php.symfony.request.files", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$request->files`, ObjectType: "Request", MethodName: "files", Description: "Symfony uploaded files bag", Assigns: "return"},

		// CodeIgniter framework sources
		{ID: "php.codeigniter.input.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$this->input->get\s*\(`, ObjectType: "CI_Input", MethodName: "get", Description: "CodeIgniter input->get() user data", Assigns: "return"},
		{ID: "php.codeigniter.input.post", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$this->input->post\s*\(`, ObjectType: "CI_Input", MethodName: "post", Description: "CodeIgniter input->post() user data", Assigns: "return"},
		{ID: "php.codeigniter.input.cookie", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\$this->input->cookie\s*\(`, ObjectType: "CI_Input", MethodName: "cookie", Description: "CodeIgniter input->cookie() user data", Assigns: "return"},

		// WordPress sources
		// add_query_arg()/remove_query_arg() return a URL built from the CURRENT
		// request URI ($_SERVER['REQUEST_URI']) when called WITHOUT an explicit
		// third URL argument, and — critically — WordPress does NOT escape the
		// returned value. Echoing it directly (`echo add_query_arg('p', 1);`) is
		// reflected XSS, one of the most common WordPress-plugin vulnerability
		// classes (hundreds of WPVDB entries; the WP docs explicitly warn to wrap
		// the result in esc_url()). Modelled as a user-input SOURCE so flow into
		// echo/print (SnkHTMLOutput) reports, while the esc_url / esc_url_raw
		// sanitizers (already in the catalog) keep the correct `esc_url(
		// add_query_arg(...))` idiom clean.
		{ID: "php.wordpress.add_query_arg", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\badd_query_arg\s*\(`, ObjectType: "", MethodName: "add_query_arg", Description: "WordPress add_query_arg() returns the unescaped current request URI — echoing it is reflected XSS (wrap in esc_url())", Assigns: "return"},
		{ID: "php.wordpress.remove_query_arg", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `\bremove_query_arg\s*\(`, ObjectType: "", MethodName: "remove_query_arg", Description: "WordPress remove_query_arg() returns the unescaped current request URI — echoing it is reflected XSS (wrap in esc_url())", Assigns: "return"},
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
		// AWS DynamoDB read sources (aws-sdk-php DynamoDbClient) — second-order taint: items
		// written on an earlier request and read back later carry attacker-controlled
		// attribute values into downstream sinks. ObjectType "DynamoDbClient" mirrors the
		// existing php.aws.dynamodb.executestatement sink; Pattern is scoped to the canonical
		// $dynamoDb/$ddb receiver for the Layer-1 regex fallback (tsflow matches on ObjectType).
		{ID: "php.aws.dynamodb.getitem", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\$(?:dynamo|ddb)\w*\s*->\s*getItem\s*\(`, ObjectType: "DynamoDbClient", MethodName: "getItem", Description: "AWS DynamoDB GetItem result (second-order; item attributes may be attacker-controlled)", Assigns: "return"},
		{ID: "php.aws.dynamodb.query", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\$(?:dynamo|ddb)\w*\s*->\s*query\s*\(`, ObjectType: "DynamoDbClient", MethodName: "query", Description: "AWS DynamoDB Query result items (second-order; attributes may be attacker-controlled)", Assigns: "return"},
		{ID: "php.aws.dynamodb.scan", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\$(?:dynamo|ddb)\w*\s*->\s*scan\s*\(`, ObjectType: "DynamoDbClient", MethodName: "scan", Description: "AWS DynamoDB Scan result items (second-order; attributes may be attacker-controlled)", Assigns: "return"},
		{ID: "php.aws.dynamodb.batchgetitem", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\$(?:dynamo|ddb)\w*\s*->\s*batchGetItem\s*\(`, ObjectType: "DynamoDbClient", MethodName: "batchGetItem", Description: "AWS DynamoDB BatchGetItem responses (second-order; attributes may be attacker-controlled)", Assigns: "return"},
		{ID: "php.aws.dynamodb.transactgetitems", Category: taint.SrcDatabase, Language: rules.LangPHP, Pattern: `\$(?:dynamo|ddb)\w*\s*->\s*transactGetItems\s*\(`, ObjectType: "DynamoDbClient", MethodName: "transactGetItems", Description: "AWS DynamoDB TransactGetItems responses (second-order; attributes may be attacker-controlled)", Assigns: "return"},
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

		// --- Additional Laravel sources ---
		{
			ID:          "php.laravel.request.file",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$request->file\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "file",
			Description: "Laravel uploaded file from request",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.request.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$request->cookie\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "cookie",
			Description: "Laravel cookie value from request",
			Assigns:     "return",
		},

		// --- Symfony static Request ---
		{
			ID:          "php.symfony.request.static.get",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `Request::createFromGlobals\s*\(`,
			ObjectType:  "Symfony\\HttpFoundation\\Request",
			MethodName:  "createFromGlobals",
			Description: "Symfony Request created from PHP superglobals",
			Assigns:     "return",
		},

		// --- XML from input ---
		{
			ID:          "php.simplexml.input",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPHP,
			Pattern:     `\bsimplexml_load_string\s*\(`,
			ObjectType:  "",
			MethodName:  "simplexml_load_string",
			Description: "XML parsed from potentially tainted string",
			Assigns:     "return",
		},

		// --- Database sources ---
		{
			ID:          "php.pdo.fetch",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->fetch\s*\(|->fetchAll\s*\(|->fetchColumn\s*\(`,
			ObjectType:  "PDOStatement",
			MethodName:  "fetch/fetchAll/fetchColumn",
			Description: "Database row data from PDO fetch",
			Assigns:     "return",
		},
		{
			ID:          "php.mysqli.fetch",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `mysqli_fetch_assoc\s*\(|mysqli_fetch_array\s*\(|->fetch_assoc\s*\(`,
			ObjectType:  "mysqli_result",
			MethodName:  "fetch_assoc/fetch_array",
			Description: "Database row data from mysqli fetch",
			Assigns:     "return",
		},

		// --- WordPress $wpdb database sources (second-order injection) ---
		// CVE-2022-21661, CVE-2024-27956: stored user data flows from $wpdb into sinks
		{
			ID:          "php.wordpress.wpdb.get_results",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$wpdb->get_results\s*\(`,
			ObjectType:  "wpdb",
			MethodName:  "get_results",
			Description: "WordPress database query results (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wpdb.get_var",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$wpdb->get_var\s*\(`,
			ObjectType:  "wpdb",
			MethodName:  "get_var",
			Description: "WordPress single database value (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wpdb.get_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$wpdb->get_row\s*\(`,
			ObjectType:  "wpdb",
			MethodName:  "get_row",
			Description: "WordPress single database row (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wpdb.get_col",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$wpdb->get_col\s*\(`,
			ObjectType:  "wpdb",
			MethodName:  "get_col",
			Description: "WordPress database column values (may contain stored user data)",
			Assigns:     "return",
		},

		// --- Laravel Eloquent ORM sources (second-order injection) ---
		// CVE-2020-35700: stored data retrieved via Eloquent used in raw SQL
		{
			ID:          "php.laravel.eloquent.find",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\b[A-Z]\w+::find\s*\(|\b[A-Z]\w+::findOrFail\s*\(`,
			ObjectType:  "",
			MethodName:  "find/findOrFail",
			Description: "Laravel Eloquent model lookup by ID (returns stored data)",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.eloquent.first",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\b[A-Z]\w+::firstWhere\s*\(|->first\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "firstWhere/first",
			Description: "Laravel Eloquent first matching model (returns stored data)",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.eloquent.pluck",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\b[A-Z]\w+::pluck\s*\(|->pluck\s*\(`,
			ObjectType:  "",
			MethodName:  "pluck",
			Description: "Laravel Eloquent pluck extracts raw column values from database",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.eloquent.value",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\b[A-Z]\w+::value\s*\(|->value\s*\(`,
			ObjectType:  "",
			MethodName:  "value",
			Description: "Laravel Eloquent value returns single scalar from database",
			Assigns:     "return",
		},
		// --- Doctrine ORM sources (second-order injection) ---
		{
			ID:          "php.doctrine.repository.findby",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->findBy\s*\(`,
			ObjectType:  "",
			MethodName:  "findBy",
			Description: "Doctrine repository findBy returns entities with stored data",
			Assigns:     "return",
		},
		{
			ID:          "php.doctrine.repository.findoneby",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->findOneBy\s*\(`,
			ObjectType:  "",
			MethodName:  "findOneBy",
			Description: "Doctrine repository findOneBy returns single entity with stored data",
			Assigns:     "return",
		},
		{
			ID:          "php.doctrine.query.getresult",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->getResult\s*\(|->getArrayResult\s*\(`,
			ObjectType:  "",
			MethodName:  "getResult/getArrayResult",
			Description: "Doctrine query result set (entities or arrays with stored data)",
			Assigns:     "return",
		},
		{
			ID:          "php.doctrine.query.getsingleresult",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->getSingleResult\s*\(|->getSingleScalarResult\s*\(`,
			ObjectType:  "",
			MethodName:  "getSingleResult/getSingleScalarResult",
			Description: "Doctrine single query result (entity or scalar with stored data)",
			Assigns:     "return",
		},

		// --- Redis cache sources (second-order injection) ---
		{
			ID:          "php.redis.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$redis\w*\s*->\s*get\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "get",
			Description: "Redis cached value (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.hash",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$redis\w*\s*->\s*hGet\s*\(|\$redis\w*\s*->\s*hGetAll\s*\(|\$redis\w*\s*->\s*hget\s*\(|\$redis\w*\s*->\s*hgetall\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hGet/hGetAll",
			Description: "Redis hash field value (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.list",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$redis\w*\s*->\s*lRange\s*\(|\$redis\w*\s*->\s*lrange\s*\(|\$redis\w*\s*->\s*lPop\s*\(|\$redis\w*\s*->\s*lpop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lRange/lPop",
			Description: "Redis list elements (may contain stored user data)",
			Assigns:     "return",
		},

		// --- Memcached sources (second-order injection) ---
		{
			ID:          "php.memcached.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\$memcache[d]?\s*->\s*get\s*\(`,
			ObjectType:  "Memcached",
			MethodName:  "get",
			Description: "Memcached cached value (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.memcache.procedural.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\bmemcache_get\s*\(`,
			ObjectType:  "",
			MethodName:  "memcache_get",
			Description: "Memcache procedural get (may contain stored user data)",
			Assigns:     "return",
		},

		// --- MongoDB sources (second-order injection) ---
		{
			ID:          "php.mongodb.findone",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->findOne\s*\(`,
			ObjectType:  "",
			MethodName:  "findOne",
			Description: "MongoDB document lookup (may contain stored user data)",
			Assigns:     "return",
		},
		// findOneAndUpdate/Replace/Delete return the matched document (the
		// stored value, pre- or post-mutation), so the return value carries
		// whatever a previous request persisted — classic second-order taint.
		// aggregate returns the pipeline result documents. Method names are
		// MongoDB-specific, so empty ObjectType is FP-safe (same convention as
		// php.mongodb.findone above).
		{
			ID:          "php.mongodb.findoneandupdate",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->findOneAndUpdate\s*\(`,
			ObjectType:  "",
			MethodName:  "findOneAndUpdate",
			Description: "MongoDB findOneAndUpdate returns the matched document (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.mongodb.findoneandreplace",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->findOneAndReplace\s*\(`,
			ObjectType:  "",
			MethodName:  "findOneAndReplace",
			Description: "MongoDB findOneAndReplace returns the matched document (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.mongodb.findoneanddelete",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->findOneAndDelete\s*\(`,
			ObjectType:  "",
			MethodName:  "findOneAndDelete",
			Description: "MongoDB findOneAndDelete returns the deleted document (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.mongodb.aggregate",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->aggregate\s*\(`,
			ObjectType:  "",
			MethodName:  "aggregate",
			Description: "MongoDB aggregation pipeline results (may contain stored user data)",
			Assigns:     "return",
		},

		// --- Network / HTTP client response sources ---
		{
			ID:          "php.curl.exec.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bcurl_exec\s*\(`,
			ObjectType:  "",
			MethodName:  "curl_exec",
			Description: "curl HTTP response body (CURLOPT_RETURNTRANSFER)",
			Assigns:     "return",
		},
		{
			ID:          "php.curl.multi.getcontent",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bcurl_multi_getcontent\s*\(`,
			ObjectType:  "",
			MethodName:  "curl_multi_getcontent",
			Description: "Multi-curl response content extraction",
			Assigns:     "return",
		},
		{
			ID:          "php.guzzle.response.getbody",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `->getBody\s*\(`,
			ObjectType:  "Psr\\Http\\Message\\ResponseInterface",
			MethodName:  "getBody",
			Description: "PSR-7/Guzzle HTTP response body stream",
			Assigns:     "return",
		},
		{
			ID:          "php.stream.get_contents",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bstream_get_contents\s*\(`,
			ObjectType:  "",
			MethodName:  "stream_get_contents",
			Description: "Stream content read (often wraps HTTP/socket streams)",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wp_remote_get",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bwp_remote_get\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_remote_get",
			Description: "WordPress HTTP GET response array",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wp_remote_post",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bwp_remote_post\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_remote_post",
			Description: "WordPress HTTP POST response array",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wp_remote_request",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bwp_remote_request\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_remote_request",
			Description: "WordPress generic HTTP request response array",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.wp_remote_retrieve_body",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bwp_remote_retrieve_body\s*\(`,
			ObjectType:  "",
			MethodName:  "wp_remote_retrieve_body",
			Description: "WordPress HTTP response body extraction",
			Assigns:     "return",
		},
		{
			ID:          "php.socket.read",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bsocket_read\s*\(`,
			ObjectType:  "",
			MethodName:  "socket_read",
			Description: "Raw TCP socket data read",
			Assigns:     "return",
		},
		{
			ID:          "php.socket.recv",
			Category:    taint.SrcNetwork,
			Language:    rules.LangPHP,
			Pattern:     `\bsocket_recv\s*\(`,
			ObjectType:  "",
			MethodName:  "socket_recv",
			Description: "Raw TCP socket data receive",
			Assigns:     "return",
		},

		// --- PSR-7 ServerRequestInterface sources (Slim 4, Laminas, Mezzio, CakePHP 4+) ---
		{
			ID:          "php.psr7.getparsedbody",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getParsedBody\s*\(`,
			ObjectType:  "Psr\\Http\\Message\\ServerRequestInterface",
			MethodName:  "getParsedBody",
			Description: "PSR-7 parsed request body (POST params, JSON body)",
			Assigns:     "return",
		},
		// --- PSR-7 ServerRequest sources (Slim, Laminas, Mezzio, any PSR-7 framework) ---
		{
			ID:          "php.psr7.getqueryparams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getQueryParams\s*\(`,
			ObjectType:  "Psr\\Http\\Message\\ServerRequestInterface",
			MethodName:  "getQueryParams",
			Description: "PSR-7 query string parameters",
			Assigns:     "return",
		},
		{
			ID:          "php.psr7.getcookieparams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getCookieParams\s*\(`,
			ObjectType:  "Psr\\Http\\Message\\ServerRequestInterface",
			MethodName:  "getCookieParams",
			Description: "PSR-7 cookie parameters",
			Assigns:     "return",
		},
		{
			ID:          "php.psr7.getparsedbody",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getParsedBody\s*\(`,
			ObjectType:  "ServerRequest",
			MethodName:  "getParsedBody",
			Description: "PSR-7 ServerRequest parsed body ($_POST equivalent)",
			Assigns:     "return",
		},
		{
			ID:          "php.psr7.getuploadedfiles",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getUploadedFiles\s*\(`,
			ObjectType:  "Psr\\Http\\Message\\ServerRequestInterface",
			MethodName:  "getUploadedFiles",
			Description: "PSR-7 uploaded files collection",
			Assigns:     "return",
		},
		{
			ID:          "php.psr7.getheaderline",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getHeaderLine\s*\(`,
			ObjectType:  "ServerRequest",
			MethodName:  "getHeaderLine",
			Description: "PSR-7 specific HTTP header value",
			Assigns:     "return",
		},
		{
			ID:          "php.psr7.getserverparams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getServerParams\s*\(`,
			ObjectType:  "Psr\\Http\\Message\\ServerRequestInterface",
			MethodName:  "getServerParams",
			Description: "PSR-7 server parameters ($_SERVER equivalent)",
			Assigns:     "return",
		},

		// --- CakePHP sources (Cake\Http\ServerRequest) ---
		{
			ID:          "php.cakephp.getdata",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getData\s*\(`,
			ObjectType:  "ServerRequest",
			MethodName:  "getData",
			Description: "CakePHP request POST/body data",
			Assigns:     "return",
		},
		{
			ID:          "php.cakephp.getquery",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getQuery\s*\(`,
			ObjectType:  "ServerRequest",
			MethodName:  "getQuery",
			Description: "CakePHP request query string parameters",
			Assigns:     "return",
		},
		{
			ID:          "php.cakephp.getcookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getCookie\s*\(`,
			ObjectType:  "ServerRequest",
			MethodName:  "getCookie",
			Description: "CakePHP request cookie value",
			Assigns:     "return",
		},

		// --- Yii2 sources (yii\web\Request) ---
		{
			ID:          "php.yii2.request.get",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `Yii::\$app->request->get\s*\(`,
			ObjectType:  "Request",
			MethodName:  "get",
			Description: "Yii2 GET request parameter",
			Assigns:     "return",
		},
		{
			ID:          "php.yii2.request.post",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `Yii::\$app->request->post\s*\(`,
			ObjectType:  "Request",
			MethodName:  "post",
			Description: "Yii2 POST request parameter",
			Assigns:     "return",
		},
		{
			ID:          "php.yii2.request.bodyparams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `Yii::\$app->request->bodyParams`,
			ObjectType:  "Request",
			MethodName:  "bodyParams",
			Description: "Yii2 all body parameters",
			Assigns:     "return",
		},
		{
			ID:          "php.yii2.request.queryparams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `Yii::\$app->request->queryParams`,
			ObjectType:  "Request",
			MethodName:  "queryParams",
			Description: "Yii2 all query string parameters",
			Assigns:     "return",
		},

		// --- Phalcon sources (Phalcon\Http\Request, DI service "request") ---
		// Phalcon controllers/tasks read untrusted input through the
		// DI-injected request service: $this->request->getQuery(...),
		// $this->request->getPost(...), $request->get(...), etc. ObjectType
		// "Request" scopes these to a request receiver so they do not match
		// arbitrary ->get/->getQuery calls on unrelated objects.
		{
			ID:          "php.phalcon.request.get",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->get\s*\(`,
			ObjectType:  "Request",
			MethodName:  "get",
			Description: "Phalcon Request::get() request value",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getquery",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getQuery\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getQuery",
			Description: "Phalcon Request::getQuery() GET parameter ($_GET)",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getpost",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getPost\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getPost",
			Description: "Phalcon Request::getPost() POST parameter ($_POST)",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getput",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getPut\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getPut",
			Description: "Phalcon Request::getPut() PUT body parameter",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getserver",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getServer\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getServer",
			Description: "Phalcon Request::getServer() $_SERVER value",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getrawbody",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getRawBody\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getRawBody",
			Description: "Phalcon Request::getRawBody() raw HTTP request body",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getjsonrawbody",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getJsonRawBody\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getJsonRawBody",
			Description: "Phalcon Request::getJsonRawBody() decoded JSON request body",
			Assigns:     "return",
		},
		{
			ID:          "php.phalcon.request.getheader",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$(?:this->)?request->getHeader\s*\(`,
			ObjectType:  "Request",
			MethodName:  "getHeader",
			Description: "Phalcon Request::getHeader() request header value",
			Assigns:     "return",
		},

		// --- Additional superglobals ---
		{
			ID:          "php.superglobal.server.path_info",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$_SERVER\s*\[\s*['"]PATH_INFO['"]`,
			ObjectType:  "",
			MethodName:  "$_SERVER[PATH_INFO]",
			Description: "PATH_INFO from URL (user-controlled, used in routing)",
			Assigns:     "return",
		},
		{
			ID:          "php.superglobal.server.php_self",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$_SERVER\s*\[\s*['"]PHP_SELF['"]`,
			ObjectType:  "",
			MethodName:  "$_SERVER[PHP_SELF]",
			Description: "PHP_SELF script path (classic XSS vector via PATH_INFO injection)",
			Assigns:     "return",
		},
		{
			ID:          "php.superglobal.session",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `\$_SESSION\s*\[`,
			ObjectType:  "",
			MethodName:  "$_SESSION",
			Description: "Session data (may contain attacker-controlled values from prior requests)",
			Assigns:     "return",
		},

		// --- Laravel additional sources ---
		{
			ID:          "php.laravel.request.ip",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$request->ip\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "ip",
			Description: "Laravel client IP (spoofable via X-Forwarded-For with trusted proxies)",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.request.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$request->path\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "path",
			Description: "Laravel request URI path",
			Assigns:     "return",
		},
		{
			ID:          "php.laravel.request.segment",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$request->segment\s*\(`,
			ObjectType:  "Illuminate\\Http\\Request",
			MethodName:  "segment",
			Description: "Laravel URL segment by index (user-controlled path component)",
			Assigns:     "return",
		},
		{
			ID:          "php.psr7.getcookieparams",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `->getCookieParams\s*\(`,
			ObjectType:  "ServerRequest",
			MethodName:  "getCookieParams",
			Description: "PSR-7 ServerRequest cookie parameters ($_COOKIE equivalent)",
			Assigns:     "return",
		},

		// --- Redis data sources (phpredis / Predis) ---
		{
			ID:          "php.redis.hget",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->hGet\s*\(|->hGetAll\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hGet/hGetAll",
			Description: "Redis hash field read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.lrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->lRange\s*\(|->lPop\s*\(|->rPop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lRange/lPop/rPop",
			Description: "Redis list element read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.smembers",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->sMembers\s*\(|->sPop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "sMembers/sPop",
			Description: "Redis set member read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.zrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->zRange\s*\(|->zRangeByScore\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zRange/zRangeByScore",
			Description: "Redis sorted set range read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.mget",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->mGet\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "mGet",
			Description: "Redis multi-key read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.hkeys",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->hKeys\s*\(|->hVals\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hKeys/hVals",
			Description: "Redis hash keys/values list read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.hmget",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->hMGet\s*\(|->hMget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hMGet/hMget",
			Description: "Redis hash multi-field read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.lindex",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->lIndex\s*\(|->lGet\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lIndex/lGet",
			Description: "Redis list element read by index (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.srandmember",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->sRandMember\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "sRandMember",
			Description: "Redis random set member read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.zrevrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->zRevRange\s*\(|->zRevRangeByScore\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zRevRange/zRevRangeByScore",
			Description: "Redis reverse sorted set range read (potentially untrusted cached data)",
			Assigns:     "return",
		},
		{
			ID:          "php.redis.getrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->getRange\s*\(|->substr\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "getRange/substr",
			Description: "Redis string substring read (potentially untrusted cached data)",
			Assigns:     "return",
		},

		// --- Memcached source ---
		{
			ID:          "php.memcached.getmulti",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->getMulti\s*\(`,
			ObjectType:  "",
			MethodName:  "getMulti",
			Description: "Memcached multi-key read (potentially untrusted cached data)",
			Assigns:     "return",
		},

		// --- AMQP / RabbitMQ sources (php-amqplib) ---
		{
			ID:          "php.amqplib.basic_get",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->basic_get\s*\(`,
			ObjectType:  "",
			MethodName:  "basic_get",
			Description: "AMQP channel basic_get — returns message from queue",
			Assigns:     "return",
		},
		{
			ID:          "php.amqplib.basic_consume",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->basic_consume\s*\(`,
			ObjectType:  "",
			MethodName:  "basic_consume",
			Description: "AMQP channel basic_consume — sets up queue consumer callback with untrusted message data",
			Assigns:     "return",
		},

		// --- Kafka source (php-rdkafka) ---
		{
			ID:          "php.rdkafka.consume",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `->consume\s*\(\s*\d`,
			ObjectType:  "KafkaConsumer",
			MethodName:  "consume",
			Description: "Kafka consumer message read (rdkafka extension)",
			Assigns:     "return",
		},

		// --- YAML deserialization source ---
		{
			ID:          "php.yaml.parse",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangPHP,
			Pattern:     `\byaml_parse\s*\(|Yaml::parse\s*\(`,
			ObjectType:  "",
			MethodName:  "yaml_parse/Yaml::parse",
			Description: "YAML parsing — deserialized data from potentially untrusted input",
			Assigns:     "return",
		},

		// --- Drupal 10+ Form API sources ---
		{
			ID:          "php.drupal.formstate.getvalue",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$form_state->getValue\s*\(`,
			ObjectType:  "FormStateInterface",
			MethodName:  "getValue",
			Description: "Drupal Form API user input via FormState::getValue()",
			Assigns:     "return",
		},
		{
			ID:          "php.drupal.formstate.getvalues",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$form_state->getValues\s*\(`,
			ObjectType:  "FormStateInterface",
			MethodName:  "getValues",
			Description: "Drupal Form API all user input via FormState::getValues()",
			Assigns:     "return",
		},
		{
			ID:          "php.drupal.formstate.getuserinput",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$form_state->getUserInput\s*\(`,
			ObjectType:  "FormStateInterface",
			MethodName:  "getUserInput",
			Description: "Drupal raw unvalidated form input via FormState::getUserInput()",
			Assigns:     "return",
		},

		// --- WordPress REST API request input sources (WP_REST_Request) ---
		// The WP REST API powers headless WordPress, Gutenberg blocks, and
		// thousands of plugins. Route handlers receive a WP_REST_Request whose
		// snake_case getters return user-controlled HTTP request data. CVE
		// references include CVE-2023-32243 (Essential Addons) and many others
		// where get_param/get_json_params reached SQL/eval/wp_remote_get sinks.
		{
			ID:          "php.wordpress.rest.request.get_param",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_param\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_param",
			Description: "WordPress REST API parameter (URL/body/JSON) via WP_REST_Request::get_param()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_query_params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_query_params\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_query_params",
			Description: "WordPress REST API URL query parameters via WP_REST_Request::get_query_params()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_body_params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_body_params\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_body_params",
			Description: "WordPress REST API form-encoded body params via WP_REST_Request::get_body_params()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_json_params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_json_params\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_json_params",
			Description: "WordPress REST API JSON body params via WP_REST_Request::get_json_params()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_url_params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_url_params\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_url_params",
			Description: "WordPress REST API route URL parameters via WP_REST_Request::get_url_params()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_file_params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_file_params\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_file_params",
			Description: "WordPress REST API uploaded files via WP_REST_Request::get_file_params()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_header\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_header",
			Description: "WordPress REST API single header value via WP_REST_Request::get_header()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_headers\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_headers",
			Description: "WordPress REST API all headers via WP_REST_Request::get_headers()",
			Assigns:     "return",
		},
		{
			ID:          "php.wordpress.rest.request.get_body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `\$re(?:quest|q)->get_body\s*\(`,
			ObjectType:  "WP_REST_Request",
			MethodName:  "get_body",
			Description: "WordPress REST API raw request body via WP_REST_Request::get_body()",
			Assigns:     "return",
		},

		// --- Native PostgreSQL (pgsql ext) row fetches (second-order injection) ---
		// pg_fetch_* return rows previously written to the DB; attacker-stored
		// data flowing back out into a SQL/command/HTML sink is second-order.
		{
			ID:          "php.pg.fetch",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\bpg_fetch_assoc\s*\(|\bpg_fetch_array\s*\(|\bpg_fetch_row\s*\(|\bpg_fetch_object\s*\(`,
			ObjectType:  "",
			MethodName:  "pg_fetch_assoc/pg_fetch_array/pg_fetch_row/pg_fetch_object",
			Description: "PostgreSQL row data from pg_fetch_* (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.pg.fetch_all",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\bpg_fetch_all\s*\(|\bpg_fetch_all_columns\s*\(|\bpg_fetch_result\s*\(`,
			ObjectType:  "",
			MethodName:  "pg_fetch_all/pg_fetch_all_columns/pg_fetch_result",
			Description: "PostgreSQL result set from pg_fetch_all / pg_fetch_result (may contain stored user data)",
			Assigns:     "return",
		},

		// --- mysqli additional row fetches (second-order injection) ---
		// Complements php.mysqli.fetch (fetch_assoc/fetch_array) with the
		// object/row/all variants in both procedural and OO forms.
		{
			ID:          "php.mysqli.fetch_object_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `\bmysqli_fetch_object\s*\(|\bmysqli_fetch_row\s*\(|\bmysqli_fetch_all\s*\(|\bmysqli_fetch_column\s*\(|->fetch_object\s*\(|->fetch_row\s*\(|->fetch_all\s*\(|->fetch_column\s*\(`,
			ObjectType:  "",
			MethodName:  "mysqli_fetch_object/mysqli_fetch_row/mysqli_fetch_all/mysqli_fetch_column/fetch_object/fetch_row/fetch_all/fetch_column",
			Description: "Database row data from mysqli fetch_object/fetch_row/fetch_all/fetch_column",
			Assigns:     "return",
		},

		// --- Doctrine DBAL Connection/Result read methods (second-order injection) ---
		// Doctrine DBAL is the database abstraction underpinning Symfony, API
		// Platform, Sylius and Akeneo. The fetch* methods return rows previously
		// written to the DB; reading attacker-stored data back into a sink is
		// second-order injection. (These same methods are also SQLi sinks at
		// arg 0 — that's the orthogonal first-order direction.)
		{
			ID:          "php.doctrine.dbal.fetchassociative",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->\s*fetchAssociative\s*\(|->\s*fetchAllAssociative\s*\(|->\s*fetchAllAssociativeIndexed\s*\(|->\s*fetchAllKeyValue\s*\(`,
			ObjectType:  "",
			MethodName:  "fetchAssociative/fetchAllAssociative/fetchAllAssociativeIndexed/fetchAllKeyValue",
			Description: "Doctrine DBAL associative result rows (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.doctrine.dbal.fetchnumeric",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->\s*fetchNumeric\s*\(|->\s*fetchAllNumeric\s*\(|->\s*fetchOne\s*\(|->\s*fetchFirstColumn\s*\(`,
			ObjectType:  "",
			MethodName:  "fetchNumeric/fetchAllNumeric/fetchOne/fetchFirstColumn",
			Description: "Doctrine DBAL numeric/scalar result data (may contain stored user data)",
			Assigns:     "return",
		},

		// --- CodeIgniter 4 ResultInterface row generators (second-order injection) ---
		// $db->query(...)->getResultArray() etc. return rows from the DB. The bare
		// getResult() is already covered by php.doctrine.query.getresult.
		{
			ID:          "php.codeigniter.result.getarray",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->\s*getResultArray\s*\(|->\s*getRowArray\s*\(`,
			ObjectType:  "",
			MethodName:  "getResultArray/getRowArray",
			Description: "CodeIgniter 4 query result rows as arrays (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.codeigniter.result.getobject",
			Category:    taint.SrcDatabase,
			Language:    rules.LangPHP,
			Pattern:     `->\s*getResultObject\s*\(|->\s*getRowObject\s*\(|->\s*getCustomResultObject\s*\(|->\s*getCustomRowObject\s*\(`,
			ObjectType:  "",
			MethodName:  "getResultObject/getRowObject/getCustomResultObject/getCustomRowObject",
			Description: "CodeIgniter 4 query result rows as objects (may contain stored user data)",
			Assigns:     "return",
		},

		// --- Additional Laravel / Symfony / Slim / Yii / WordPress request sources ---

		// Laravel
		{ID: "php.laravel.request.input", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->input\s*\(`, ObjectType: "Illuminate\\Http\\Request", MethodName: "input", Description: "Laravel Request->input($key) — query/body parameter accessor", Assigns: "return"},
		{ID: "php.laravel.request.all", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->all\s*\(\s*\)`, ObjectType: "Illuminate\\Http\\Request", MethodName: "all", Description: "Laravel Request->all() — every query/body parameter as array", Assigns: "return"},
		{ID: "php.laravel.request.only", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->only\s*\(|->except\s*\(`, ObjectType: "Illuminate\\Http\\Request", MethodName: "only/except", Description: "Laravel Request->only / ->except — filtered parameter accessors (still tainted)", Assigns: "return"},
		{ID: "php.laravel.request.json_method", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->json\s*\(`, ObjectType: "Illuminate\\Http\\Request", MethodName: "json", Description: "Laravel Request->json($key) — JSON body accessor", Assigns: "return"},
		{ID: "php.laravel.request.query_method", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->query\s*\(`, ObjectType: "Illuminate\\Http\\Request", MethodName: "query", Description: "Laravel Request->query() — query-string parameters", Assigns: "return"},
		{ID: "php.laravel.request.header_method", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->header\s*\(`, ObjectType: "Illuminate\\Http\\Request", MethodName: "header", Description: "Laravel Request->header($name) — single request header", Assigns: "return"},
		{ID: "php.laravel.request.cookie_method", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->cookie\s*\(`, ObjectType: "Illuminate\\Http\\Request", MethodName: "cookie", Description: "Laravel Request->cookie($name) — cookie accessor", Assigns: "return"},
		{ID: "php.laravel.request.path", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->path\s*\(\s*\)|->fullUrl\s*\(\s*\)|->url\s*\(\s*\)`, ObjectType: "Illuminate\\Http\\Request", MethodName: "path/fullUrl/url", Description: "Laravel Request->path / ->fullUrl / ->url — URL components", Assigns: "return"},

		// Symfony
		{ID: "php.symfony.request.query_get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->query->get\s*\(|->query->all\s*\(`, ObjectType: "Symfony\\Component\\HttpFoundation\\Request", MethodName: "query.get/all", Description: "Symfony Request->query->get / ->all — query string parameters (ParameterBag)", Assigns: "return"},
		{ID: "php.symfony.request.request_get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->request->get\s*\(|->request->all\s*\(`, ObjectType: "Symfony\\Component\\HttpFoundation\\Request", MethodName: "request.get/all", Description: "Symfony Request->request->get / ->all — POST body parameters", Assigns: "return"},
		{ID: "php.symfony.request.attributes_get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->attributes->get\s*\(`, ObjectType: "Symfony\\Component\\HttpFoundation\\Request", MethodName: "attributes.get", Description: "Symfony Request->attributes->get — route attributes (path-bound parameters)", Assigns: "return"},
		{ID: "php.symfony.request.headers_get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->headers->get\s*\(|->headers->all\s*\(`, ObjectType: "Symfony\\Component\\HttpFoundation\\Request", MethodName: "headers.get/all", Description: "Symfony Request->headers — HeaderBag accessor", Assigns: "return"},
		{ID: "php.symfony.request.cookies_get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->cookies->get\s*\(`, ObjectType: "Symfony\\Component\\HttpFoundation\\Request", MethodName: "cookies.get", Description: "Symfony Request->cookies->get — cookie value", Assigns: "return"},
		{ID: "php.symfony.request.getcontent", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->getContent\s*\(`, ObjectType: "Symfony\\Component\\HttpFoundation\\Request", MethodName: "getContent", Description: "Symfony Request->getContent() — raw body string", Assigns: "return"},

		// Slim 4 / PSR-7
		{ID: "php.slim.request.getparsedbody", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->getParsedBody\s*\(\s*\)`, ObjectType: "Psr\\Http\\Message\\ServerRequestInterface", MethodName: "getParsedBody", Description: "PSR-7 ServerRequest->getParsedBody() — parsed body (JSON/form)", Assigns: "return"},
		{ID: "php.slim.request.getqueryparams", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->getQueryParams\s*\(\s*\)`, ObjectType: "Psr\\Http\\Message\\ServerRequestInterface", MethodName: "getQueryParams", Description: "PSR-7 ServerRequest->getQueryParams() — URL query parameters", Assigns: "return"},
		{ID: "php.slim.request.getheaderline", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->getHeaderLine\s*\(|->getHeader\s*\(`, ObjectType: "Psr\\Http\\Message\\ServerRequestInterface", MethodName: "getHeaderLine/getHeader", Description: "PSR-7 ServerRequest header accessors", Assigns: "return"},
		{ID: "php.slim.request.getuploadedfiles", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->getUploadedFiles\s*\(\s*\)`, ObjectType: "Psr\\Http\\Message\\ServerRequestInterface", MethodName: "getUploadedFiles", Description: "PSR-7 ServerRequest->getUploadedFiles() — uploaded file array", Assigns: "return"},

		// Yii 2
		{ID: "php.yii.request.get", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->get\s*\(|->post\s*\(`, ObjectType: "yii\\web\\Request", MethodName: "get/post", Description: "Yii 2 Request->get / ->post — request parameters", Assigns: "return"},
		{ID: "php.yii.request.headers_method", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->getHeaders\s*\(\s*\)`, ObjectType: "yii\\web\\Request", MethodName: "getHeaders", Description: "Yii 2 Request->getHeaders() — header collection", Assigns: "return"},

		// WordPress
		{ID: "php.wordpress.rest.request.get_param", Category: taint.SrcUserInput, Language: rules.LangPHP, Pattern: `->get_param\s*\(|->get_params\s*\(\s*\)`, ObjectType: "WP_REST_Request", MethodName: "get_param/get_params", Description: "WordPress WP_REST_Request->get_param / ->get_params — REST endpoint parameters", Assigns: "return"},

		// --- webonyx/graphql-php resolver arguments ---
		// In graphql-php a field resolver is `fn($root, $args, $context,
		// ResolveInfo $info)` — whether a closure or a method. The 2nd
		// positional parameter, $args, is the client-supplied field-argument
		// array (fully attacker-controlled query variables). To avoid matching
		// every PHP function that happens to take a $args parameter, the source
		// requires the distinctive webonyx `ResolveInfo` parameter to appear in
		// the same signature. Refs: https://webonyx.github.io/graphql-php/
		{
			ID:          "php.graphql.resolver.args",
			Category:    taint.SrcUserInput,
			Language:    rules.LangPHP,
			Pattern:     `function\s*\w*\s*\([^)]*\$args[^)]*ResolveInfo`,
			ObjectType:  "GraphQL\\Type\\Definition\\ResolveInfo",
			MethodName:  "resolve($root, $args, $context, ResolveInfo $info)",
			Description: "webonyx/graphql-php resolver $args — client-supplied GraphQL field arguments (user-controlled)",
			Assigns:     "return",
		},

		// --- PHP in-memory user-cache read sources (second-order injection) ---
		// APCu / APC / WinCache / XCache user caches store arbitrary application
		// data that is frequently attacker-influenced (serialized session blobs,
		// rendered fragments, queued job payloads). Reading that data back out
		// into a SQL / command / eval / deserialization sink is second-order
		// injection — the same pattern already modeled for the Redis and
		// Memcached read sources above. These are plain global functions whose
		// return value is the cached value, so no receiver is involved and the
		// distinctive names carry zero false-positive risk.
		{
			ID:          "php.apcu.fetch",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `\bapcu_fetch\s*\(|\bapcu_entry\s*\(`,
			ObjectType:  "",
			MethodName:  "apcu_fetch/apcu_entry",
			Description: "APCu user-cache value via apcu_fetch/apcu_entry (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.apc.fetch",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `\bapc_fetch\s*\(`,
			ObjectType:  "",
			MethodName:  "apc_fetch",
			Description: "APC user-cache value via apc_fetch (legacy APC extension; may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.wincache.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `\bwincache_ucache_get\s*\(`,
			ObjectType:  "",
			MethodName:  "wincache_ucache_get",
			Description: "WinCache user-cache value via wincache_ucache_get (Windows PHP; may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "php.xcache.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangPHP,
			Pattern:     `\bxcache_get\s*\(`,
			ObjectType:  "",
			MethodName:  "xcache_get",
			Description: "XCache user-cache value via xcache_get (may contain stored user data)",
			Assigns:     "return",
		},
	}
}
