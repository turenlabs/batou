package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (c *RustCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- Actix-web framework input ---
		{
			ID:          "rust.actix.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `web::Query`,
			ObjectType:  "actix_web",
			MethodName:  "web::Query",
			Description: "Actix-web query parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.actix.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `web::Path`,
			ObjectType:  "actix_web",
			MethodName:  "web::Path",
			Description: "Actix-web URL path parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.actix.json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `web::Json`,
			ObjectType:  "actix_web",
			MethodName:  "web::Json",
			Description: "Actix-web JSON request body extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.actix.form",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `web::Form`,
			ObjectType:  "actix_web",
			MethodName:  "web::Form",
			Description: "Actix-web form data extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.actix.request",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `HttpRequest`,
			ObjectType:  "actix_web",
			MethodName:  "HttpRequest",
			Description: "Actix-web HTTP request object",
			Assigns:     "return",
		},

		// --- Axum framework input ---
		{
			ID:          "rust.axum.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::Query`,
			ObjectType:  "axum",
			MethodName:  "extract::Query",
			Description: "Axum query parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::Path`,
			ObjectType:  "axum",
			MethodName:  "extract::Path",
			Description: "Axum URL path parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::Json`,
			ObjectType:  "axum",
			MethodName:  "extract::Json",
			Description: "Axum JSON request body extraction",
			Assigns:     "return",
		},

		// --- Rocket framework input ---
		{
			ID:          "rust.rocket.param",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `#\[get\(`,
			ObjectType:  "rocket",
			MethodName:  "#[get] route parameter",
			Description: "Rocket framework route parameter from attribute",
			Assigns:     "return",
		},

		// --- Warp framework input ---
		{
			ID:          "rust.warp.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::query`,
			ObjectType:  "warp",
			MethodName:  "warp::query",
			Description: "Warp query parameter filter",
			Assigns:     "return",
		},
		{
			ID:          "rust.warp.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::body`,
			ObjectType:  "warp",
			MethodName:  "warp::body",
			Description: "Warp request body filter",
			Assigns:     "return",
		},

		// --- Hyper ---
		{
			ID:          "rust.hyper.request",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `hyper::Request`,
			ObjectType:  "hyper",
			MethodName:  "hyper::Request",
			Description: "Hyper HTTP request object",
			Assigns:     "return",
		},

		// --- Standard library input ---
		{
			ID:          "rust.std.env.args",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangRust,
			Pattern:     `std::env::args\s*\(`,
			ObjectType:  "",
			MethodName:  "std::env::args",
			Description: "Command-line arguments iterator",
			Assigns:     "return",
		},
		{
			ID:          "rust.std.env.var",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangRust,
			Pattern:     `std::env::var\s*\(`,
			ObjectType:  "",
			MethodName:  "std::env::var",
			Description: "Environment variable value",
			Assigns:     "return",
		},
		{
			ID:          "rust.std.env.var_short",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangRust,
			Pattern:     `env::var\s*\(`,
			ObjectType:  "",
			MethodName:  "env::var",
			Description: "Environment variable value (short import)",
			Assigns:     "return",
		},
		{
			ID:          "rust.std.io.stdin",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `std::io::stdin\s*\(`,
			ObjectType:  "",
			MethodName:  "std::io::stdin",
			Description: "Standard input stream",
			Assigns:     "return",
		},
		{
			ID:          "rust.std.io.stdin_read",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `stdin\(\)\s*\.\s*read_line\s*\(`,
			ObjectType:  "",
			MethodName:  "stdin().read_line",
			Description: "Read line from standard input",
			Assigns:     "arg:0",
		},

		// --- File input ---
		{
			ID:          "rust.std.fs.read_to_string",
			Category:    taint.SrcFileRead,
			Language:    rules.LangRust,
			Pattern:     `fs::read_to_string\s*\(`,
			ObjectType:  "",
			MethodName:  "fs::read_to_string",
			Description: "File contents read as string",
			Assigns:     "return",
		},
		{
			ID:          "rust.std.fs.read",
			Category:    taint.SrcFileRead,
			Language:    rules.LangRust,
			Pattern:     `fs::read\s*\(`,
			ObjectType:  "",
			MethodName:  "fs::read",
			Description: "File contents read as bytes",
			Assigns:     "return",
		},

		// --- Network input ---
		{
			ID:          "rust.tokio.net.read",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRust,
			Pattern:     `\.read\s*\(\s*&mut\s+`,
			ObjectType:  "TcpStream",
			MethodName:  "TcpStream::read",
			Description: "Network socket read",
			Assigns:     "arg:0",
		},

		// --- Deserialization ---
		{
			ID:          "rust.serde.from_str",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRust,
			Pattern:     `serde_json::from_str\s*\(`,
			ObjectType:  "serde_json",
			MethodName:  "serde_json::from_str",
			Description: "JSON deserialization from string",
			Assigns:     "return",
		},
		{
			ID:          "rust.serde.from_slice",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRust,
			Pattern:     `serde_json::from_slice\s*\(`,
			ObjectType:  "serde_json",
			MethodName:  "serde_json::from_slice",
			Description: "JSON deserialization from byte slice",
			Assigns:     "return",
		},

		// --- Actix-web headers/cookies ---
		{
			ID:          "rust.actix.headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `req\.headers\(\)|\.get_header\(`,
			ObjectType:  "actix_web",
			MethodName:  "headers",
			Description: "Actix-web request headers",
			Assigns:     "return",
		},
		{
			ID:          "rust.actix.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `req\.cookie\s*\(`,
			ObjectType:  "actix_web",
			MethodName:  "cookie",
			Description: "Actix-web request cookie",
			Assigns:     "return",
		},

		// --- Axum Form/headers ---
		{
			ID:          "rust.axum.form",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::Form`,
			ObjectType:  "axum",
			MethodName:  "extract::Form",
			Description: "Axum form data extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::TypedHeader|HeaderMap`,
			ObjectType:  "axum",
			MethodName:  "TypedHeader/HeaderMap",
			Description: "Axum request headers extraction",
			Assigns:     "return",
		},

		// --- Warp path/header ---
		{
			ID:          "rust.warp.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::path::param`,
			ObjectType:  "warp",
			MethodName:  "warp::path::param",
			Description: "Warp path parameter filter",
			Assigns:     "return",
		},
		{
			ID:          "rust.warp.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::header`,
			ObjectType:  "warp",
			MethodName:  "warp::header",
			Description: "Warp header filter",
			Assigns:     "return",
		},

		// --- Poem framework ---
		{
			ID:          "rust.poem.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `poem::web::Query|poem::web::Form|poem::web::Json`,
			ObjectType:  "poem",
			MethodName:  "poem::web::Query/Form/Json",
			Description: "Poem framework input extraction",
			Assigns:     "return",
		},

		// --- Tide framework ---
		{
			ID:          "rust.tide.request",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `req\.query\s*\(|req\.body_string\s*\(|req\.body_json\s*\(`,
			ObjectType:  "tide",
			MethodName:  "tide request",
			Description: "Tide framework request input",
			Assigns:     "return",
		},

		// --- TOML/YAML deserialization ---
		{
			ID:          "rust.toml.from_str",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRust,
			Pattern:     `toml::from_str\s*\(|serde_yaml::from_str\s*\(|serde_yaml::from_reader\s*\(`,
			ObjectType:  "toml/serde_yaml",
			MethodName:  "toml/yaml::from_str",
			Description: "TOML or YAML deserialization from string",
			Assigns:     "return",
		},

		// --- Additional Rust sources ---
		{
			ID:          "rust.rocket.form",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `Form<|FromForm`,
			ObjectType:  "rocket::form",
			MethodName:  "Form/FromForm",
			Description: "Rocket framework form data",
			Assigns:     "return",
		},
		{
			ID:          "rust.tokio.io.read",
			Category:    taint.SrcNetwork,
			Language:    rules.LangRust,
			Pattern:     `AsyncReadExt.*\.read\s*\(|\.read_to_string\s*\(`,
			ObjectType:  "tokio::io",
			MethodName:  "read/read_to_string",
			Description: "Tokio async read from potentially untrusted source",
			Assigns:     "return",
		},
		{
			ID:          "rust.serde.from_str_combined",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangRust,
			Pattern:     `serde_json::from_str\s*\(|serde_json::from_slice\s*\(|serde_json::from_reader\s*\(`,
			ObjectType:  "serde_json",
			MethodName:  "from_str/from_slice/from_reader",
			Description: "Serde JSON deserialization from potentially untrusted data",
			Assigns:     "return",
		},
	}
}
