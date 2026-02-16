package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
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
	}
}
