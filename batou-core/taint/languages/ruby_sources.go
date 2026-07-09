package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (rubyCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// Rails request sources
		{ID: "ruby.rails.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\s*\[`, ObjectType: "ActionController", MethodName: "params[]", Description: "Rails request parameters", Assigns: "return"},
		{ID: "ruby.rails.params.fetch", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\.fetch\s*\(`, ObjectType: "ActionController", MethodName: "params.fetch", Description: "Rails params.fetch", Assigns: "return"},
		{ID: "ruby.rails.params.require", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\.require\s*\(`, ObjectType: "ActionController", MethodName: "params.require", Description: "Rails params.require (strong parameters)", Assigns: "return"},
		{ID: "ruby.rails.request.headers", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.headers\s*\[`, ObjectType: "ActionDispatch::Request", MethodName: "headers[]", Description: "Rails request headers", Assigns: "return"},
		{ID: "ruby.rails.request.cookies", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.cookies\s*\[`, ObjectType: "ActionDispatch::Request", MethodName: "cookies[]", Description: "Rails request cookies", Assigns: "return"},
		{ID: "ruby.rails.request.body", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.body`, ObjectType: "ActionDispatch::Request", MethodName: "body", Description: "Rails request body", Assigns: "return"},
		{ID: "ruby.rails.request.raw_post", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.raw_post`, ObjectType: "ActionDispatch::Request", MethodName: "raw_post", Description: "Rails raw POST body", Assigns: "return"},

		// CLI/stdin
		{ID: "ruby.argv", Category: taint.SrcCLIArg, Language: rules.LangRuby, Pattern: `\bARGV`, ObjectType: "", MethodName: "ARGV", Description: "Command-line arguments", Assigns: "return"},
		{ID: "ruby.stdin.gets", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `STDIN\.gets`, ObjectType: "STDIN", MethodName: "gets", Description: "Standard input read", Assigns: "return"},

		// Environment
		{ID: "ruby.env", Category: taint.SrcEnvVar, Language: rules.LangRuby, Pattern: `ENV\s*\[`, ObjectType: "", MethodName: "ENV[]", Description: "Environment variable", Assigns: "return"},

		// File sources
		{ID: "ruby.file.read", Category: taint.SrcFileRead, Language: rules.LangRuby, Pattern: `File\.read\s*\(`, ObjectType: "File", MethodName: "read", Description: "File read", Assigns: "return"},
		{ID: "ruby.io.read", Category: taint.SrcFileRead, Language: rules.LangRuby, Pattern: `IO\.read\s*\(`, ObjectType: "IO", MethodName: "read", Description: "IO read", Assigns: "return"},

		// Sinatra sources
		{ID: "ruby.sinatra.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\s*\[`, ObjectType: "Sinatra::Base", MethodName: "params[]", Description: "Sinatra request parameters", Assigns: "return"},
		{ID: "ruby.sinatra.request.body.read", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.body\.read`, ObjectType: "Sinatra::Request", MethodName: "body.read", Description: "Sinatra request body read", Assigns: "return"},
		{ID: "ruby.sinatra.request.env", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.env\s*\[`, ObjectType: "Sinatra::Request", MethodName: "env[]", Description: "Sinatra request environment variables", Assigns: "return"},

		// Grape sources
		{ID: "ruby.grape.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\s*\[`, ObjectType: "Grape::API", MethodName: "params[]", Description: "Grape API request parameters", Assigns: "return"},
		{ID: "ruby.grape.declared_params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `declared_params`, ObjectType: "Grape::API", MethodName: "declared_params", Description: "Grape declared parameters", Assigns: "return"},

		// Hanami sources
		{ID: "ruby.hanami.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\s*\[`, ObjectType: "Hanami::Action", MethodName: "params[]", Description: "Hanami action parameters", Assigns: "return"},

		// Rack sources
		{ID: "ruby.rack.request.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `Rack::Request\.new\s*\(`, ObjectType: "Rack::Request", MethodName: "new", Description: "Rack request object with user input", Assigns: "return"},
		{ID: "ruby.rack.env.query_string", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `env\s*\[\s*['"]QUERY_STRING['"]\s*\]`, ObjectType: "Rack", MethodName: "env['QUERY_STRING']", Description: "Rack query string from environment", Assigns: "return"},
		{ID: "ruby.rack.env.rack_input", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `env\s*\[\s*['"]rack\.input['"]\s*\]`, ObjectType: "Rack", MethodName: "env['rack.input']", Description: "Rack input stream from environment", Assigns: "return"},

		// ActionCable sources
		{ID: "ruby.actioncable.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\s*\[`, ObjectType: "ActionCable::Channel", MethodName: "params[]", Description: "ActionCable channel parameters", Assigns: "return"},

		// JSON deserialization source
		{ID: "ruby.json.parse", Category: taint.SrcDeserialized, Language: rules.LangRuby, Pattern: `JSON\.parse\s*\(`, ObjectType: "JSON", MethodName: "parse", Description: "Parsed JSON data from untrusted input", Assigns: "return"},

		// AWS Lambda event source (Jets framework)
		{ID: "ruby.aws.lambda.event", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `def\s+handler\s*\(\s*event:.*context:`, ObjectType: "aws-sdk-lambda", MethodName: "handler event", Description: "AWS Lambda event data from external trigger", Assigns: "return"},
		// AWS SQS message source
		{ID: "ruby.aws.sqs.receive", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.receive_message\s*\(`, ObjectType: "Aws::SQS::Client", MethodName: "receive_message", Description: "AWS SQS message data from queue", Assigns: "return"},
		// AWS S3 object source
		{ID: "ruby.aws.s3.getobject", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.get_object\s*\(`, ObjectType: "Aws::S3::Client", MethodName: "get_object", Description: "AWS S3 object data from potentially untrusted bucket", Assigns: "return"},
		// AWS DynamoDB read sources (aws-sdk-dynamodb) — second-order/stored taint:
		// data written by one request and read back by a later one. Low-level
		// Aws::DynamoDB::Client (idiomatically bound to `client`) and the high-level
		// Aws::DynamoDB::Resource table handle (bound to `table`). Method names are
		// DynamoDB-distinctive; the generic verbs query/scan are attached ONLY to the
		// Table ObjectType so they can't fire on arbitrary `.query()`/`.scan()` calls.
		{ID: "ruby.aws.dynamodb.client.get_item", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.get_item\s*\(`, ObjectType: "Aws::DynamoDB::Client", MethodName: "get_item", Description: "AWS DynamoDB Client#get_item — item read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.client.batch_get_item", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.batch_get_item\s*\(`, ObjectType: "Aws::DynamoDB::Client", MethodName: "batch_get_item", Description: "AWS DynamoDB Client#batch_get_item — items read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.client.transact_get_items", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.transact_get_items\s*\(`, ObjectType: "Aws::DynamoDB::Client", MethodName: "transact_get_items", Description: "AWS DynamoDB Client#transact_get_items — items read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.client.execute_statement", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.execute_statement\s*\(`, ObjectType: "Aws::DynamoDB::Client", MethodName: "execute_statement", Description: "AWS DynamoDB Client#execute_statement (PartiQL) — items read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.client.batch_execute_statement", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.batch_execute_statement\s*\(`, ObjectType: "Aws::DynamoDB::Client", MethodName: "batch_execute_statement", Description: "AWS DynamoDB Client#batch_execute_statement (PartiQL) — items read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.table.get_item", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.get_item\s*\(`, ObjectType: "Aws::DynamoDB::Table", MethodName: "get_item", Description: "AWS DynamoDB Table#get_item — item read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.table.query", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.query\s*\(`, ObjectType: "Aws::DynamoDB::Table", MethodName: "query", Description: "AWS DynamoDB Table#query — items read back from table (second-order taint)", Assigns: "return"},
		{ID: "ruby.aws.dynamodb.table.scan", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `\.scan\s*\(`, ObjectType: "Aws::DynamoDB::Table", MethodName: "scan", Description: "AWS DynamoDB Table#scan — items read back from table (second-order taint)", Assigns: "return"},
		// GCP Pub/Sub source
		{ID: "ruby.gcp.pubsub.pull", Category: taint.SrcExternal, Language: rules.LangRuby, Pattern: `subscription\.pull`, ObjectType: "Google::Cloud::PubSub", MethodName: "pull", Description: "GCP Pub/Sub message data", Assigns: "return"},

		// Additional Rails request sources
		{ID: "ruby.rails.request.referer", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.referer|request\.referrer`, ObjectType: "ActionDispatch::Request", MethodName: "referer", Description: "Rails request referer header", Assigns: "return"},
		{ID: "ruby.rails.request.user_agent", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.user_agent`, ObjectType: "ActionDispatch::Request", MethodName: "user_agent", Description: "Rails request user agent header", Assigns: "return"},
		{ID: "ruby.rails.request.remote_ip", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.remote_ip`, ObjectType: "ActionDispatch::Request", MethodName: "remote_ip", Description: "Rails request remote IP", Assigns: "return"},
		{ID: "ruby.rack.env.path_info", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `env\s*\[\s*['"]PATH_INFO['"]\s*\]`, ObjectType: "Rack", MethodName: "env['PATH_INFO']", Description: "Rack PATH_INFO from environment", Assigns: "return"},

		// --- Standard library ---
		{
			ID:          "ruby.env.fetch",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangRuby,
			Pattern:     `ENV\.fetch\s*\(|ENV\[`,
			ObjectType:  "ENV",
			MethodName:  "fetch/[]",
			Description: "Environment variable access",
			Assigns:     "return",
		},
		{
			ID:          "ruby.file.readlines",
			Category:    taint.SrcFileRead,
			Language:    rules.LangRuby,
			Pattern:     `File\.readlines\s*\(|IO\.readlines\s*\(`,
			ObjectType:  "File",
			MethodName:  "readlines",
			Description: "File read lines into array",
			Assigns:     "return",
		},
		{
			ID:          "ruby.net.http.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `Net::HTTP\.get\s*\(|\.body\b`,
			ObjectType:  "Net::HTTP",
			MethodName:  "get/body",
			Description: "HTTP response body from network request",
			Assigns:     "return",
		},
		{
			ID:          "ruby.csv.parse",
			Category:    taint.SrcFileRead,
			Language:    rules.LangRuby,
			Pattern:     `CSV\.parse\s*\(|CSV\.read\s*\(`,
			ObjectType:  "CSV",
			MethodName:  "parse/read",
			Description: "CSV parsed data from potentially untrusted source",
			Assigns:     "return",
		},

		// --- Rails additional sources ---
		{
			ID:          "ruby.rails.request.fullpath",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.fullpath|request\.original_url|request\.url`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "fullpath/original_url/url",
			Description: "Rails request full path or URL",
			Assigns:     "return",
		},

		// --- Rails cookies ---
		{
			ID:          "ruby.rails.cookies.source",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `cookies\s*\[`,
			ObjectType:  "ActionDispatch::Cookies",
			MethodName:  "cookies[]",
			Description: "Rails cookie value (user-controlled)",
			Assigns:     "return",
		},

		// --- ActionDispatch uploaded file ---
		{
			ID:          "ruby.rails.upload",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `ActionDispatch::Http::UploadedFile|\.original_filename`,
			ObjectType:  "ActionDispatch::Http::UploadedFile",
			MethodName:  "UploadedFile",
			Description: "Rails uploaded file data and filename",
			Assigns:     "return",
		},
		// The `.original_filename` READER on an uploaded-file object
		// (`file.original_filename`) is the attacker-controlled upload filename
		// (Rack::Multipart / ActionDispatch::Http::UploadedFile). The entry
		// above keys the dataflow matcher under the constructor name
		// "UploadedFile", so the structural tsflow walker — which keys sources on
		// the called METHOD name — never seeds `file.original_filename`
		// (extractCallName yields "original_filename", not "UploadedFile"), and
		// the regex Pattern only helps the Layer-1 engine. This companion entry
		// keys under the reader method so the dataflow engine seeds it too.
		// ObjectType is empty because the receiver is an arbitrary local
		// (`file`, `upload`, `f`, `params[:doc]`); `original_filename` is a
		// upload-unique method name (Rack/ActionDispatch uploaded files only),
		// so a bare-name match carries no realistic FP. Reading the filename and
		// passing it to a shell exec / file sink is the railsgoat command-
		// injection shape (CWE-78).
		{
			ID:          "ruby.rails.upload.original_filename",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `\.original_filename\b`,
			ObjectType:  "",
			MethodName:  "original_filename",
			Description: "Rails/Rack uploaded file original filename (attacker-controlled)",
			Assigns:     "return",
		},

		// --- Rack::Request ---
		{
			ID:          "ruby.rack.request.get",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `Rack::Request\.new\s*\(.*\.params|rack_request\.params`,
			ObjectType:  "Rack::Request",
			MethodName:  "params",
			Description: "Rack request parameters",
			Assigns:     "return",
		},

		// --- Sinatra params ---
		{
			ID:          "ruby.sinatra.params.source",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `params\.fetch\s*\(`,
			ObjectType:  "Sinatra::Base",
			MethodName:  "params.fetch",
			Description: "Sinatra parameter fetch",
			Assigns:     "return",
		},

		// --- Redis get from user key ---
		{
			ID:          "ruby.redis.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.get\s*\(|Redis\.current\.get\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "get",
			Description: "Redis value from potentially user-controlled key",
			Assigns:     "return",
		},

		// --- Sidekiq worker args ---
		{
			ID:          "ruby.sidekiq.worker.args",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `def\s+perform\s*\(`,
			ObjectType:  "Sidekiq::Worker",
			MethodName:  "perform",
			Description: "Sidekiq worker arguments from job queue",
			Assigns:     "return",
		},

		// --- RabbitMQ / Bunny sources ---
		{
			ID:          "ruby.bunny.basic_get",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `\.basic_get\s*\(`,
			ObjectType:  "Channel",
			MethodName:  "basic_get",
			Description: "Bunny RabbitMQ basic.get message from queue",
			Assigns:     "return",
		},
		{
			ID:          "ruby.bunny.basic_consume",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `\.basic_consume\s*\(`,
			ObjectType:  "Channel",
			MethodName:  "basic_consume",
			Description: "Bunny RabbitMQ basic.consume subscription (message from queue)",
			Assigns:     "return",
		},

		// --- Memcached / Dalli sources ---
		{
			ID:          "ruby.dalli.get",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `(?:dalli|mc|memcache)\.get\s*\(`,
			ObjectType:  "Dalli",
			MethodName:  "get",
			Description: "Dalli Memcached get value from external cache",
			Assigns:     "return",
		},
		{
			ID:          "ruby.dalli.get_multi",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `\.get_multi\s*\(`,
			ObjectType:  "Dalli",
			MethodName:  "get_multi",
			Description: "Dalli Memcached multi-get values from external cache",
			Assigns:     "return",
		},

		// --- ActiveSupport::Cache (Rails.cache) read sources (second-order) ---
		// Rails.cache / ActiveSupport::Cache::Store is the dominant Rails caching
		// API, backed by memcached, Redis, file, or memory stores. Values returned
		// by read/fetch come from data previously written by application or
		// external code, often under user-controlled keys, so they are second-order
		// taint sources: a cached profile field replayed into SQL, a cached URL
		// fetched server-side (SSRF), a cached command string passed to system().
		// The Dalli entries above only cover the raw memcached client; this covers
		// the framework-level cache abstraction that most Rails apps actually use.
		// https://api.rubyonrails.org/classes/ActiveSupport/Cache/Store.html
		{
			ID:          "ruby.activesupport.cache.read",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `(?:Rails\.cache|@?cache)\.read\s*\(`,
			ObjectType:  "ActiveSupport::Cache",
			MethodName:  "read",
			Description: "ActiveSupport::Cache#read — value from the Rails cache store (second-order, user-controllable)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activesupport.cache.fetch",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `(?:Rails\.cache|@?cache)\.fetch\s*\(`,
			ObjectType:  "ActiveSupport::Cache",
			MethodName:  "fetch",
			Description: "ActiveSupport::Cache#fetch — cached value (or block result) from the Rails cache store (second-order)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activesupport.cache.read_multi",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `(?:Rails\.cache|@?cache)\.read_multi\s*\(`,
			ObjectType:  "ActiveSupport::Cache",
			MethodName:  "read_multi",
			Description: "ActiveSupport::Cache#read_multi — hash of cached values from the Rails cache store (second-order)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activesupport.cache.fetch_multi",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `(?:Rails\.cache|@?cache)\.fetch_multi\s*\(`,
			ObjectType:  "ActiveSupport::Cache",
			MethodName:  "fetch_multi",
			Description: "ActiveSupport::Cache#fetch_multi — hash of cached values from the Rails cache store (second-order)",
			Assigns:     "return",
		},

		// --- Kafka sources ---
		{
			ID:          "ruby.kafka.each_message",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `\.each_message\s*(?:do|\{)`,
			ObjectType:  "Consumer",
			MethodName:  "each_message",
			Description: "ruby-kafka consumer message from Kafka topic",
			Assigns:     "return",
		},

		// --- Sneakers (RabbitMQ worker framework) ---
		{
			ID:          "ruby.sneakers.work",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `def\s+work\s*\(`,
			ObjectType:  "",
			MethodName:  "work",
			Description: "Sneakers RabbitMQ worker message argument",
			Assigns:     "return",
		},

		// --- NATS sources ---
		{
			ID:          "ruby.nats.subscribe",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `nats\.subscribe\s*\(`,
			ObjectType:  "NATS",
			MethodName:  "subscribe",
			Description: "NATS message subscription data from external broker",
			Assigns:     "return",
		},

		// --- Additional Redis sources ---
		{
			ID:          "ruby.redis.hget",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.hget\s*\(|Redis\.current\.hget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hget",
			Description: "Redis hash field value from external cache",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.hgetall",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.hgetall\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hgetall",
			Description: "Redis hash all fields from external cache",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.lpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.(?:lpop|rpop|brpop|blpop)\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lpop/rpop/brpop/blpop",
			Description: "Redis list pop operations returning external data",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.smembers",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.smembers\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "smembers",
			Description: "Redis set members from external cache",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.mget",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.mget\s*\(|Redis\.current\.mget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "mget",
			Description: "Redis multi-get values from external cache",
			Assigns:     "return",
		},

		// --- Additional redis-rb read commands (second-order taint) ---
		// These return data previously stored by application or external code.
		// Treating them as taint sources catches stored-XSS, command-injection
		// via queued job names, SQL-injection via cached search terms, etc.
		{
			ID:          "ruby.redis.hkeys",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.hkeys\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hkeys",
			Description: "Redis hash field names from external cache (HKEYS)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.hvals",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.hvals\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hvals",
			Description: "Redis hash values from external cache (HVALS)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.hmget",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.hmget\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "hmget",
			Description: "Redis hash multi-field values from external cache (HMGET)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.lrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.lrange\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lrange",
			Description: "Redis list range elements from external cache (LRANGE)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.lindex",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.lindex\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "lindex",
			Description: "Redis list element at index from external cache (LINDEX)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.srandmember",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.srandmember\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "srandmember",
			Description: "Redis random set member from external cache (SRANDMEMBER)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.spop",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.spop\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "spop",
			Description: "Redis set pop returns removed member (SPOP)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.zrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.zrange\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zrange",
			Description: "Redis sorted-set range from external cache (ZRANGE)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.zrevrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.zrevrange\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zrevrange",
			Description: "Redis sorted-set reverse range from external cache (ZREVRANGE)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.zrangebyscore",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.zrangebyscore\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zrangebyscore",
			Description: "Redis sorted-set range by score from external cache (ZRANGEBYSCORE)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.zpopmin",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.zpopmin\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zpopmin",
			Description: "Redis sorted-set pop lowest-scored member (ZPOPMIN)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.redis.zpopmax",
			Category:    taint.SrcExternal,
			Language:    rules.LangRuby,
			Pattern:     `redis\.zpopmax\s*\(`,
			ObjectType:  "Redis",
			MethodName:  "zpopmax",
			Description: "Redis sorted-set pop highest-scored member (ZPOPMAX)",
			Assigns:     "return",
		},

		// --- Rails request path/query/host sources ---
		{
			ID:          "ruby.rails.request.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.path\b|request\.path_info`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "path/path_info",
			Description: "Rails request URL path (user-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.rails.request.query_string",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.query_string`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "query_string",
			Description: "Rails raw query string",
			Assigns:     "return",
		},
		{
			ID:          "ruby.rails.request.host",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.host\b`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "host",
			Description: "Rails request Host header (user-controlled, cache poisoning risk)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.rails.request.content_type",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.content_type`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "content_type",
			Description: "Rails request Content-Type header",
			Assigns:     "return",
		},

		// --- Roda framework sources ---
		{
			ID:          "ruby.roda.request.params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `(?:^|[^\w])r\.params\s*\[|request\.params\s*\[`,
			ObjectType:  "Roda::RodaRequest",
			MethodName:  "params[]",
			Description: "Roda framework request parameters",
			Assigns:     "return",
		},

		// --- Additional Rails request sources ---
		{
			ID:          "ruby.rails.request.query_string",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.query_string`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "query_string",
			Description: "Rails request raw query string",
			Assigns:     "return",
		},
		{
			ID:          "ruby.rails.request.url",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.url\b|request\.original_url`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "url/original_url",
			Description: "Rails full request URL (user-controlled)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.rails.request.fullpath",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `request\.fullpath|request\.original_fullpath`,
			ObjectType:  "ActionDispatch::Request",
			MethodName:  "fullpath/original_fullpath",
			Description: "Rails request path with query string",
			Assigns:     "return",
		},

		// --- Rack environment HTTP headers ---
		{
			ID:          "ruby.rack.env.http_header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `env\s*\[\s*['"]HTTP_`,
			ObjectType:  "Rack",
			MethodName:  "env['HTTP_*']",
			Description: "Rack HTTP header from environment (all client headers)",
			Assigns:     "return",
		},

		// --- HTTP response body as source (SSRF chain) ---
		{
			ID:          "ruby.net_http.response.body",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `Net::HTTP\.get_response\s*\(|\.body\b`,
			ObjectType:  "Net::HTTPResponse",
			MethodName:  "body",
			Description: "HTTP response body from Net::HTTP (potentially untrusted external data)",
			Assigns:     "return",
		},

		// --- Database result sources (second-order injection) ---

		// ActiveRecord query result sources
		{
			ID:          "ruby.activerecord.find_by.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.find_by\s*\(`,
			ObjectType:  "",
			MethodName:  "find_by",
			Description: "ActiveRecord find_by result (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activerecord.pluck.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.pluck\s*\(`,
			ObjectType:  "",
			MethodName:  "pluck",
			Description: "ActiveRecord pluck extracts raw column values from database",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activerecord.pick.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.pick\s*\(`,
			ObjectType:  "",
			MethodName:  "pick",
			Description: "ActiveRecord pick extracts single value from first row",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activerecord.select_values.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.select_values\s*\(`,
			ObjectType:  "",
			MethodName:  "select_values",
			Description: "ActiveRecord connection select_values returns column values array",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activerecord.select_value.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.select_value\s*\(`,
			ObjectType:  "",
			MethodName:  "select_value",
			Description: "ActiveRecord connection select_value returns single scalar",
			Assigns:     "return",
		},

		// PG gem (PostgreSQL) result sources
		{
			ID:          "ruby.pg.exec_params.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.exec_params\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "exec_params",
			Description: "PG::Connection exec_params returns PG::Result with database rows",
			Assigns:     "return",
		},
		{
			ID:          "ruby.pg.async_exec.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.async_exec\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "async_exec",
			Description: "PG::Connection async_exec returns PG::Result with database rows",
			Assigns:     "return",
		},
		{
			ID:          "ruby.pg.exec.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.exec\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "exec",
			Description: "PG::Connection#exec returns PG::Result rows (stored user data flows back into the app)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.pg.query.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.query\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "query",
			Description: "PG::Connection#query (alias of #exec) returns PG::Result rows containing previously stored data",
			Assigns:     "return",
		},
		{
			ID:          "ruby.pg.sync_exec.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.sync_exec\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "sync_exec",
			Description: "PG::Connection#sync_exec returns PG::Result rows containing previously stored data",
			Assigns:     "return",
		},
		{
			ID:          "ruby.pg.exec_prepared.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.exec_prepared\s*\(`,
			ObjectType:  "PG::Connection",
			MethodName:  "exec_prepared",
			Description: "PG::Connection#exec_prepared returns PG::Result rows containing previously stored data",
			Assigns:     "return",
		},

		// Mysql2 gem result sources (raw MySQL driver — second-order injection)
		{
			ID:          "ruby.mysql2.query.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.query\s*\(`,
			ObjectType:  "Mysql2::Client",
			MethodName:  "query",
			Description: "Mysql2::Client#query returns a Mysql2::Result whose rows carry data stored on earlier requests",
			Assigns:     "return",
		},

		// TinyTds gem result sources (FreeTDS / SQL Server — second-order injection)
		{
			ID:          "ruby.tiny_tds.execute.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.execute\s*\(`,
			ObjectType:  "TinyTds::Client",
			MethodName:  "execute",
			Description: "TinyTds::Client#execute returns a TinyTds::Result whose rows carry data stored on earlier requests",
			Assigns:     "return",
		},

		// Apache Cassandra (DataStax cassandra-driver gem) result source — second-order CQL injection.
		// Cassandra::Session#execute is also a CQL-injection sink (ruby.cassandra.session.execute); the
		// rows it returns carry user data stored on an earlier request and flow back into later sinks.
		// ObjectType "Cassandra::Session" mirrors the existing ruby.cassandra.session.* sinks (receivers
		// session / cassandra_session / cluster_session / cas_session).
		{
			ID:          "ruby.cassandra.session.execute.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.execute\s*\(`,
			ObjectType:  "Cassandra::Session",
			MethodName:  "execute",
			Description: "Cassandra::Session#execute returns a Cassandra::Result whose rows carry data stored on earlier requests (second-order CQL injection)",
			Assigns:     "return",
		},

		// Neo4j graph-driver result sources — second-order Cypher injection / data flow-back.
		// Both methods are also Cypher-injection sinks (ruby.neo4j.driver.execute_query,
		// ruby.neo4j.active_base.run_query); the records they return carry user-stored graph data.
		{
			ID:          "ruby.neo4j.driver.execute_query.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.execute_query\s*\(`,
			ObjectType:  "Neo4j::Driver",
			MethodName:  "execute_query",
			Description: "Neo4j::Driver#execute_query (v5+ unified API) returns an EagerResult whose records carry data stored on earlier requests",
			Assigns:     "return",
		},
		{
			ID:          "ruby.neo4j.active_base.run_query.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `Neo4j::ActiveBase\.run_query\s*\(`,
			ObjectType:  "",
			MethodName:  "run_query",
			Description: "Neo4j::ActiveBase.run_query returns query result records carrying data stored on earlier requests (second-order Cypher injection)",
			Assigns:     "return",
		},

		// MongoDB ruby driver result sources (second-order NoSQL injection / data flow-back)
		// ObjectType "Mongo::Collection" mirrors the existing ruby.mongo.collection.* sinks.
		{
			ID:          "ruby.mongo.collection.find.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.find\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "find",
			Description: "Mongo::Collection#find returns a cursor over stored BSON documents (user data read back)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.mongo.collection.find_one.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.find_one\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "find_one",
			Description: "Mongo::Collection#find_one returns a stored BSON document (user data read back)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.mongo.collection.aggregate.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.aggregate\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "aggregate",
			Description: "Mongo::Collection#aggregate returns a cursor over computed documents derived from stored data",
			Assigns:     "return",
		},
		{
			ID:          "ruby.mongo.collection.distinct.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.distinct\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "distinct",
			Description: "Mongo::Collection#distinct returns an array of stored field values (user data read back)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.mongo.collection.find_one_and_update.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.find_one_and_update\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "find_one_and_update",
			Description: "Mongo::Collection#find_one_and_update returns the matched/updated BSON document (user data read back)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.mongo.collection.find_one_and_replace.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.find_one_and_replace\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "find_one_and_replace",
			Description: "Mongo::Collection#find_one_and_replace returns the matched/replaced BSON document (user data read back)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.mongo.collection.find_one_and_delete.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.find_one_and_delete\s*\(`,
			ObjectType:  "Mongo::Collection",
			MethodName:  "find_one_and_delete",
			Description: "Mongo::Collection#find_one_and_delete returns the deleted BSON document (user data read back)",
			Assigns:     "return",
		},

		// SQLite3 gem result sources
		{
			ID:          "ruby.sqlite3.get_first_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.get_first_row\s*\(`,
			ObjectType:  "SQLite3::Database",
			MethodName:  "get_first_row",
			Description: "SQLite3 get_first_row returns first result row from query",
			Assigns:     "return",
		},
		{
			ID:          "ruby.sqlite3.get_first_value",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.get_first_value\s*\(`,
			ObjectType:  "SQLite3::Database",
			MethodName:  "get_first_value",
			Description: "SQLite3 get_first_value returns single value from first row",
			Assigns:     "return",
		},

		// --- Sequel ORM result sources (second-order injection) ---
		// ObjectType "" matches any receiver (same convention as ActiveRecord entries)
		{
			ID:          "ruby.sequel.dataset.first",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `DB\[.*\]\.first\b`,
			ObjectType:  "",
			MethodName:  "first",
			Description: "Sequel dataset first row (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.sequel.dataset.all",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `DB\[.*\]\.all\b`,
			ObjectType:  "",
			MethodName:  "all",
			Description: "Sequel dataset all rows (may contain stored user data)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.sequel.dataset.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `DB\[.*\]\.get\s*\(`,
			ObjectType:  "",
			MethodName:  "get",
			Description: "Sequel dataset single column value from first row",
			Assigns:     "return",
		},
		{
			ID:          "ruby.sequel.dataset.select_map",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.select_map\s*\(`,
			ObjectType:  "",
			MethodName:  "select_map",
			Description: "Sequel dataset column values array",
			Assigns:     "return",
		},

		// --- Deserialization result sources ---
		{
			ID:          "ruby.yaml.safe_load.result",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `YAML\.safe_load\s*\(`,
			ObjectType:  "YAML",
			MethodName:  "safe_load",
			Description: "YAML.safe_load parsed data (safe deserializer but data is still untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.msgpack.unpack",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `MessagePack\.unpack\s*\(`,
			ObjectType:  "MessagePack",
			MethodName:  "unpack",
			Description: "MessagePack binary deserialized data from untrusted source",
			Assigns:     "return",
		},

		// --- HTTP client response sources (SSRF chain / untrusted external data) ---
		// parsed_response is unique to HTTParty — safe with ObjectType ""
		{
			ID:          "ruby.httparty.parsed_response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `\.parsed_response\b`,
			ObjectType:  "",
			MethodName:  "parsed_response",
			Description: "HTTParty auto-parsed response body (JSON/XML from external service)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.uri.open",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `URI\.open\s*\(`,
			ObjectType:  "URI",
			MethodName:  "open",
			Description: "URI.open response content from external URL (open-uri stdlib)",
		},

		// --- Deserialization result sources (output is attacker-controlled) ---

		{
			ID:          "ruby.yaml.load.result",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `YAML\.load\s*\(`,
			ObjectType:  "YAML",
			MethodName:  "load",
			Description: "YAML.load result may contain attacker-controlled data (CVE-2013-0156)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.yaml.unsafe_load.result",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `YAML\.unsafe_load\s*\(`,
			ObjectType:  "YAML",
			MethodName:  "unsafe_load",
			Description: "YAML.unsafe_load result contains attacker-controlled objects (Ruby 3.1+)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.marshal.load.result",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `Marshal\.(?:load|restore)\s*\(`,
			ObjectType:  "Marshal",
			MethodName:  "load/restore",
			Description: "Marshal.load result contains attacker-controlled objects (RCE risk)",
			Assigns:     "return",
		},
		{
			ID:          "ruby.oj.load.result",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `Oj\.load\s*\(`,
			ObjectType:  "Oj",
			MethodName:  "load",
			Description: "Oj.load result may contain attacker-controlled objects in :object mode",
			Assigns:     "return",
		},
		{
			ID:          "ruby.nokogiri.parse.result",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRuby,
			Pattern:     `Nokogiri::(?:XML|HTML)\s*\(`,
			ObjectType:  "Nokogiri",
			MethodName:  "XML/HTML",
			Description: "Nokogiri parsed document from untrusted XML/HTML input",
			Assigns:     "return",
		},

		// --- HTTP client response sources (response body is untrusted) ---

		{
			ID:          "ruby.faraday.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `Faraday\.(get|post|put|delete|patch)\s*\(`,
			ObjectType:  "Faraday",
			MethodName:  "get/post/put/delete/patch",
			Description: "Faraday HTTP response body from external service",
			Assigns:     "return",
		},
		{
			ID:          "ruby.httparty.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `HTTParty\.(get|post|put|delete|patch)\s*\(`,
			ObjectType:  "HTTParty",
			MethodName:  "get/post/put/delete/patch",
			Description: "HTTParty HTTP response body from external service",
			Assigns:     "return",
		},
		{
			ID:          "ruby.restclient.response",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRuby,
			Pattern:     `RestClient\.(get|post|put|delete|patch)\s*\(`,
			ObjectType:  "RestClient",
			MethodName:  "get/post/put/delete/patch",
			Description: "RestClient HTTP response from external service (String subclass)",
			Assigns:     "return",
		},

		// --- Database / ORM result sources (second-order injection) ---

		{
			ID:          "ruby.sequel.dataset.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `DB\s*\[\s*:`,
			ObjectType:  "",
			MethodName:  "DB",
			Description: "Sequel ORM dataset query result containing stored user data",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activerecord.connection.execute.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.connection\.execute\s*\(`,
			ObjectType:  "ActiveRecord::ConnectionAdapters",
			MethodName:  "connection.execute",
			Description: "ActiveRecord raw SQL execution result containing database rows",
			Assigns:     "return",
		},
		{
			ID:          "ruby.activerecord.connection.select_all.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRuby,
			Pattern:     `\.connection\.(?:select_all|select_rows)\s*\(`,
			ObjectType:  "ActiveRecord::ConnectionAdapters",
			MethodName:  "connection.select_all/select_rows",
			Description: "ActiveRecord raw SQL query result set with database rows",
			Assigns:     "return",
		},

		// --- Rails framework sources (cross-request user data) ---

		{
			ID:          "ruby.rails.session.source",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `session\s*\[`,
			ObjectType:  "",
			MethodName:  "session",
			Description: "Rails session value (may contain user-controlled data from prior requests)",
			Assigns:     "return",
		},

		// --- graphql-ruby resolver sources ---
		// graphql-ruby exposes the current GraphQL::Query via `context.query`
		// in resolvers. The Query object carries client-supplied data —
		// `.variables` is the raw operation-variables map and `.query_string`
		// is the raw query text — both fully attacker-controlled.
		{
			ID:          "ruby.graphql.query.variables",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `context\.query\.variables\b`,
			ObjectType:  "GraphQL::Query",
			MethodName:  "variables",
			Description: "graphql-ruby context.query.variables — raw operation variables submitted by the client",
			Assigns:     "return",
		},
		{
			ID:          "ruby.graphql.query.query_string",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRuby,
			Pattern:     `context\.query\.query_string\b`,
			ObjectType:  "GraphQL::Query",
			MethodName:  "query_string",
			Description: "graphql-ruby context.query.query_string — raw GraphQL query text sent by the client",
			Assigns:     "return",
		},

		// --- Additional Rails ActionDispatch / Sinatra / Hanami request sources ---
		{ID: "ruby.rails.request.fullpath", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.fullpath\b`, ObjectType: "ActionDispatch::Request", MethodName: "fullpath", Description: "Rails Request.fullpath — path + query string", Assigns: "return"},
		{ID: "ruby.rails.request.path", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.path\b`, ObjectType: "ActionDispatch::Request", MethodName: "path", Description: "Rails Request.path — URL path", Assigns: "return"},
		{ID: "ruby.rails.request.original_url", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.original_url\b|request\.original_fullpath\b`, ObjectType: "ActionDispatch::Request", MethodName: "original_url", Description: "Rails Request.original_url / original_fullpath — pre-rewriting URL", Assigns: "return"},
		{ID: "ruby.rails.request.referer", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.referer\b|request\.referrer\b`, ObjectType: "ActionDispatch::Request", MethodName: "referer", Description: "Rails Request.referer / referrer — Referer header", Assigns: "return"},
		{ID: "ruby.rails.request.user_agent", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.user_agent\b`, ObjectType: "ActionDispatch::Request", MethodName: "user_agent", Description: "Rails Request.user_agent — User-Agent header", Assigns: "return"},
		{ID: "ruby.rails.request.remote_ip", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.remote_ip\b|request\.ip\b`, ObjectType: "ActionDispatch::Request", MethodName: "remote_ip", Description: "Rails Request.remote_ip — client IP (spoofable via X-Forwarded-For)", Assigns: "return"},
		{ID: "ruby.rails.request.method_name", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.method\b|request\.request_method\b`, ObjectType: "ActionDispatch::Request", MethodName: "method", Description: "Rails Request.method — HTTP method (overridable via _method param)", Assigns: "return"},
		{ID: "ruby.rails.controller.permit", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `\.permit\s*\(|\.require\s*\(`, ObjectType: "ActionController::Parameters", MethodName: "permit/require", Description: "Rails ActionController::Parameters.permit / .require — strong-params accessor (still tainted)", Assigns: "return"},

		// Sinatra
		{ID: "ruby.sinatra.env", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `\benv\[`, ObjectType: "Sinatra::Request", MethodName: "env", Description: "Sinatra env[] — Rack env hash (HTTP_* headers, query string, body)", Assigns: "return"},
		{ID: "ruby.sinatra.request.path_info", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.path_info\b|request\.query_string\b`, ObjectType: "Sinatra::Request", MethodName: "path_info/query_string", Description: "Sinatra Request.path_info / .query_string — raw Rack accessors", Assigns: "return"},

		// Hanami
		{ID: "ruby.hanami.request.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `\.params\b`, ObjectType: "Hanami::Action::Request", MethodName: "params", Description: "Hanami Action::Request.params — merged URL/query/body parameters", Assigns: "return"},

		// Padrino (Sinatra-based full-stack framework). Routes live in
		// Padrino::Controller / Padrino::Application route blocks where request
		// input arrives via Sinatra's params hash and Rack request accessors.
		{ID: "ruby.padrino.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\s*\[`, ObjectType: "Padrino::Application", MethodName: "params[]", Description: "Padrino route-block params[] — URL/query/body request parameters", Assigns: "return"},
		{ID: "ruby.padrino.params.fetch", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `params\.fetch\s*\(`, ObjectType: "Padrino::Application", MethodName: "params.fetch", Description: "Padrino params.fetch — request parameter accessor", Assigns: "return"},
		{ID: "ruby.padrino.request.params", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.params\s*\[|request\.GET\b|request\.POST\b`, ObjectType: "Padrino::Application::Request", MethodName: "request.params", Description: "Padrino Rack request params / GET / POST — request parameters", Assigns: "return"},
		{ID: "ruby.padrino.request.body", Category: taint.SrcUserInput, Language: rules.LangRuby, Pattern: `request\.body\.read\b`, ObjectType: "Padrino::Application::Request", MethodName: "request.body.read", Description: "Padrino Rack request body read — raw request payload", Assigns: "return"},
	}
}
