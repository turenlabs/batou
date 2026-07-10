package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
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
		{
			ID:          "rust.rocket.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `rocket::form::FromForm|\bQuery<`,
			ObjectType:  "rocket",
			MethodName:  "Query<T>",
			Description: "Rocket query parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.rocket.data",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `rocket::data::Data|\bData<`,
			ObjectType:  "rocket",
			MethodName:  "Data",
			Description: "Rocket raw request body data",
			Assigns:     "return",
		},
		{
			ID:          "rust.rocket.cookies",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `CookieJar|cookies\.get\s*\(|\.get_private\s*\(`,
			ObjectType:  "rocket",
			MethodName:  "CookieJar.get",
			Description: "Rocket cookie jar value extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.rocket.headers",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `request\.headers\s*\(`,
			ObjectType:  "rocket",
			MethodName:  "request.headers",
			Description: "Rocket request headers",
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
		{
			ID:          "rust.warp.body.json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::body::json`,
			ObjectType:  "warp",
			MethodName:  "warp::body::json",
			Description: "Warp JSON body extraction filter",
			Assigns:     "return",
		},
		{
			ID:          "rust.warp.query_typed",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::query::<`,
			ObjectType:  "warp",
			MethodName:  "warp::query::<T>",
			Description: "Warp typed query parameter extraction",
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

		// --- Salvo framework (salvo.rs) input ---
		// Salvo extracts untrusted input via methods on the request object
		// (conventionally named `req`/`request`). ObjectType contains
		// "request" so the tsflow receiver heuristic binds `req`/`request`/
		// `r`/`self.request` and NOT generic ORM receivers (db/conn/pool),
		// keeping these scoped within Rust.
		{
			ID:          "rust.salvo.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.query\s*(::\s*<[^>]*>)?\s*\(|\.try_query\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "query/try_query",
			Description: "Salvo request query-string parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.param",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.param\s*(::\s*<[^>]*>)?\s*\(|\.try_param\s*(::\s*<[^>]*>)?\s*\(|\.parse_params\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "param/try_param/parse_params",
			Description: "Salvo request path/route parameter extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.form",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.form\s*(::\s*<[^>]*>)?\s*\(|\.try_form\s*(::\s*<[^>]*>)?\s*\(|\.parse_form\s*(::\s*<[^>]*>)?\s*\(|\.form_or_query\s*(::\s*<[^>]*>)?\s*\(|\.query_or_form\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "form/try_form/parse_form/form_or_query/query_or_form",
			Description: "Salvo request form-data extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.parse_json\s*(::\s*<[^>]*>)?\s*\(|\.parse_json_with_max_size\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "parse_json/parse_json_with_max_size",
			Description: "Salvo request JSON body deserialization",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.parse_body\s*(::\s*<[^>]*>)?\s*\(|\.parse_body_with_max_size\s*(::\s*<[^>]*>)?\s*\(|\.payload\s*\(|\.payload_with_max_size\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "parse_body/parse_body_with_max_size/payload/payload_with_max_size",
			Description: "Salvo request raw/auto-detected body extraction",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.header\s*(::\s*<[^>]*>)?\s*\(|\.try_header\s*(::\s*<[^>]*>)?\s*\(|\.parse_headers\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "header/try_header/parse_headers",
			Description: "Salvo request header extraction (untrusted client headers)",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.cookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.cookie\s*(::\s*<[^>]*>)?\s*\(|\.parse_cookies\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "cookie/parse_cookies",
			Description: "Salvo request cookie extraction (untrusted client cookie)",
			Assigns:     "return",
		},
		{
			ID:          "rust.salvo.extract",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\.extract\s*(::\s*<[^>]*>)?\s*\(|\.extract_with_metadata\s*(::\s*<[^>]*>)?\s*\(`,
			ObjectType:  "salvo::Request",
			MethodName:  "extract/extract_with_metadata",
			Description: "Salvo request typed extraction from multiple request parts",
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
			Pattern:     `\bForm<|FromForm`,
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

		// --- Hyper body ---
		{
			ID:          "rust.hyper.body.to_bytes",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `hyper::body::to_bytes\s*\(|body::to_bytes\s*\(`,
			ObjectType:  "hyper",
			MethodName:  "body::to_bytes",
			Description: "Hyper HTTP request body bytes",
			Assigns:     "return",
		},

		// --- Rocket FromForm ---
		{
			ID:          "rust.rocket.fromform",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `#\[derive\(.*FromForm`,
			ObjectType:  "rocket",
			MethodName:  "FromForm derive",
			Description: "Rocket framework form data via FromForm derive",
			Assigns:     "return",
		},

		// --- Warp filter query ---
		{
			ID:          "rust.warp.filter.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `warp::filters::query::query`,
			ObjectType:  "warp",
			MethodName:  "filters::query::query",
			Description: "Warp query filter extraction",
			Assigns:     "return",
		},

		// --- Axum multipart ---
		{
			ID:          "rust.axum.multipart",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::Multipart|axum::extract::Multipart`,
			ObjectType:  "axum",
			MethodName:  "extract::Multipart",
			Description: "Axum multipart form data extraction",
			Assigns:     "return",
		},

		// --- Axum extension (shared state) ---
		{
			ID:          "rust.axum.extension",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `extract::Extension|axum::extract::Extension`,
			ObjectType:  "axum",
			MethodName:  "extract::Extension",
			Description: "Axum shared state extension extraction",
			Assigns:     "return",
		},

		// --- Axum short-form extractors (no extract:: prefix) ---
		{
			ID:          "rust.axum.query_short",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `axum::extract::Query|\bQuery\(`,
			ObjectType:  "axum",
			MethodName:  "Query(params)",
			Description: "Axum query string extractor (short form)",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.path_short",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `axum::extract::Path|\bPath\(`,
			ObjectType:  "axum",
			MethodName:  "Path(params)",
			Description: "Axum URL path extractor (short form)",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.json_short",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `axum::extract::Json|\bJson\(`,
			ObjectType:  "axum",
			MethodName:  "Json(body)",
			Description: "Axum JSON body extractor (short form)",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.form_short",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `axum::extract::Form|\bForm\(`,
			ObjectType:  "axum",
			MethodName:  "Form(data)",
			Description: "Axum form data extractor (short form)",
			Assigns:     "return",
		},
		{
			ID:          "rust.axum.headers_get",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `headers\.get\s*\(`,
			ObjectType:  "axum",
			MethodName:  "headers.get",
			Description: "Axum request header value lookup",
			Assigns:     "return",
		},

		// --- std::env::args_os ---
		{
			ID:          "rust.std.env.args_os",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangRust,
			Pattern:     `std::env::args_os\s*\(|env::args_os\s*\(`,
			ObjectType:  "",
			MethodName:  "std::env::args_os",
			Description: "Command-line arguments as OsString iterator",
			Assigns:     "return",
		},

		// --- Database result sources (second-order injection) ---
		// Data read from databases may contain attacker-controlled values stored earlier.
		// These sources enable detection of second-order SQLi, XSS, and other
		// vulnerabilities where tainted data passes through a database before reaching a sink.
		// ObjectType is "" because tsflow extracts the receiver as the full chained
		// expression (e.g., "sqlx::query(...)"), not the crate name. The method names
		// are distinctive enough to avoid false positives in Rust code.

		// sqlx (async SQL toolkit — most popular Rust SQL crate)
		// --- Database result sources (SrcDatabase) ---

		// sqlx query result fetching
		{
			ID:          "rust.sqlx.fetch_one",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.fetch_one\s*\(`,
			ObjectType:  "",
			MethodName:  "fetch_one",
			Description: "sqlx single row fetch result (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.sqlx.fetch_all",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.fetch_all\s*\(`,
			ObjectType:  "",
			MethodName:  "fetch_all",
			Description: "sqlx all rows fetch result (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.sqlx.fetch_optional",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.fetch_optional\s*\(`,
			ObjectType:  "",
			MethodName:  "fetch_optional",
			Description: "sqlx optional row fetch result (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.sqlx.query_scalar",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `sqlx::query_scalar\s*\(|query_scalar\s*::<`,
			ObjectType:  "",
			MethodName:  "query_scalar",
			Description: "sqlx scalar query result (single column value from database)",
			Assigns:     "return",
		},

		// diesel (ORM / query builder)
		// Note: diesel's .load::<T>() and .first::<T>() use turbofish syntax which
		// creates generic_function AST nodes that tsflow can't extract. Only the
		// distinctive get_result/get_results methods are included here.
		{
			ID:          "rust.diesel.get_result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.get_result\s*[:<(]`,
			ObjectType:  "",
			MethodName:  "get_result",
			Description: "Diesel single row result from insert/update",
			Assigns:     "return",
		},
		{
			ID:          "rust.diesel.get_results",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.get_results\s*[:<(]`,
			ObjectType:  "",
			MethodName:  "get_results",
			Description: "Diesel multiple row results from insert/update",
			Assigns:     "return",
		},

		// rusqlite query result fetching
		{
			ID:          "rust.rusqlite.query_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.query_row\s*\(`,
			ObjectType:  "",
			MethodName:  "query_row",
			Description: "rusqlite single row query result from SQLite database",
			Assigns:     "return",
		},
		{
			ID:          "rust.rusqlite.query_map",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.query_map\s*\(`,
			ObjectType:  "",
			MethodName:  "query_map",
			Description: "rusqlite mapped query results from SQLite database",
			Assigns:     "return",
		},
		{
			ID:          "rust.rusqlite.query_and_then",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.query_and_then\s*\(`,
			ObjectType:  "",
			MethodName:  "query_and_then",
			Description: "rusqlite mapped query results with error handling from SQLite database",
			Assigns:     "return",
		},

		// tokio-postgres query result fetching
		{
			ID:          "rust.tokio_postgres.query_one",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.query_one\s*\(`,
			ObjectType:  "",
			MethodName:  "query_one",
			Description: "tokio-postgres single row query result",
			Assigns:     "return",
		},
		{
			ID:          "rust.tokio_postgres.query_opt",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.query_opt\s*\(`,
			ObjectType:  "",
			MethodName:  "query_opt",
			Description: "tokio-postgres optional row query result",
			Assigns:     "return",
		},

		// mongodb (official Rust driver)
		{
			ID:          "rust.mongodb.find_one",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.find_one\s*\(`,
			ObjectType:  "",
			MethodName:  "find_one",
			Description: "MongoDB find_one result (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mongodb.aggregate",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.aggregate\s*\(`,
			ObjectType:  "",
			MethodName:  "aggregate",
			Description: "MongoDB aggregation pipeline result cursor (documents may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mongodb.distinct",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.distinct\s*\(`,
			ObjectType:  "",
			MethodName:  "distinct",
			Description: "MongoDB distinct field values (may contain attacker-stored data)",
			Assigns:     "return",
		},
		// find_one_and_* compound operations return the matched document (by
		// default the pre-modification version), which may contain
		// attacker-stored data — a second-order taint source. The same methods
		// are also NoSQL-injection sinks (tainted filter), so these share IDs
		// with the rust_sinks.go entries (matching the find_one dual-role).
		{
			ID:          "rust.mongodb.find_one_and_update",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.find_one_and_update\s*\(`,
			ObjectType:  "",
			MethodName:  "find_one_and_update",
			Description: "MongoDB find_one_and_update returns the pre-update document (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mongodb.find_one_and_replace",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.find_one_and_replace\s*\(`,
			ObjectType:  "",
			MethodName:  "find_one_and_replace",
			Description: "MongoDB find_one_and_replace returns the pre-replacement document (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mongodb.find_one_and_delete",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.find_one_and_delete\s*\(`,
			ObjectType:  "",
			MethodName:  "find_one_and_delete",
			Description: "MongoDB find_one_and_delete returns the deleted document (may contain attacker-stored data)",
			Assigns:     "return",
		},

		// mysql / mysql_async crate (Queryable trait).
		// The query_* / exec_* methods that hand back result rows are second-order
		// data sources. The prepared-statement exec_* variants (which are *not*
		// SQL-injection sinks since the SQL text is fixed) and the fold variants
		// are covered here; the string-based query_first/query_iter/query_map names
		// are already modelled as SQL sinks in rust_sinks.go.
		{
			ID:          "rust.mysql.exec_iter",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.exec_iter\s*\(`,
			ObjectType:  "",
			MethodName:  "exec_iter",
			Description: "mysql/mysql_async Queryable::exec_iter prepared-statement result rows (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mysql.exec_map",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.exec_map\s*\(`,
			ObjectType:  "",
			MethodName:  "exec_map",
			Description: "mysql/mysql_async Queryable::exec_map mapped prepared-statement result rows (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mysql.query_fold",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.query_fold\s*\(`,
			ObjectType:  "",
			MethodName:  "query_fold",
			Description: "mysql/mysql_async Queryable::query_fold accumulator folded over result rows (may contain attacker-stored data)",
			Assigns:     "return",
		},
		{
			ID:          "rust.mysql.exec_fold",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.exec_fold\s*\(`,
			ObjectType:  "",
			MethodName:  "exec_fold",
			Description: "mysql/mysql_async Queryable::exec_fold accumulator folded over prepared-statement result rows (may contain attacker-stored data)",
			Assigns:     "return",
		},

		// --- Cloud / external data sources ---

		// AWS Lambda (lambda_runtime crate)
		// Note: LambdaEvent<T> is a type annotation, not a function call.
		// tsflow matches this via regex fallback (taint.Analyze), not AST walking.
		// For tsflow, Lambda handlers are detected via parameter naming conventions
		// (e.g., "payload", "event" + "data") that trigger seedParams.
		{
			ID:          "rust.aws.lambda.event",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `LambdaEvent\s*<`,
			ObjectType:  "",
			MethodName:  "LambdaEvent",
			Description: "AWS Lambda event data from external trigger (untrusted)",
			Assigns:     "return",
		},
		// AWS SQS (aws-sdk-sqs)
		{
			ID:          "rust.aws.sqs.receive",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.receive_message\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "receive_message",
			Description: "AWS SQS receive message builder (message body is untrusted)",
			Assigns:     "return",
		},
		// AWS S3 (aws-sdk-s3)
		{
			ID:          "rust.aws.s3.get_object",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.get_object\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "get_object",
			Description: "AWS S3 object retrieval (object content is untrusted)",
			Assigns:     "return",
		},
		// AWS DynamoDB (aws-sdk-dynamodb) read operations. The aws-sdk-rust
		// fluent builder is invoked with no positional args (client.get_item()),
		// so taint flows from the builder's return through .send().await to the
		// output. Attribute values stored by one request and read back later are
		// attacker-controlled (second-order taint). MethodNames are unique to the
		// DynamoDB API so the empty-ObjectType match is safe; query()/scan() are
		// deliberately excluded — they collide with sqlx/diesel .query() and the
		// std Iterator::scan() under tsflow's name-only matching.
		{
			ID:          "rust.aws.dynamodb.get_item",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.get_item\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "get_item",
			Description: "AWS DynamoDB GetItem result (stored attribute values are untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.aws.dynamodb.batch_get_item",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.batch_get_item\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "batch_get_item",
			Description: "AWS DynamoDB BatchGetItem result (stored attribute values are untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.aws.dynamodb.transact_get_items",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.transact_get_items\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "transact_get_items",
			Description: "AWS DynamoDB TransactGetItems result (stored attribute values are untrusted)",
			Assigns:     "return",
		},
		// AWS Kinesis (aws-sdk-kinesis) stream consumer read. GetRecords returns
		// data records produced by upstream (potentially untrusted) writers.
		{
			ID:          "rust.aws.kinesis.get_records",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.get_records\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "get_records",
			Description: "AWS Kinesis GetRecords stream data (record payloads are untrusted)",
			Assigns:     "return",
		},

		// sea-orm query result fetching
		{
			ID:          "rust.seaorm.find_by_id",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `Entity::find_by_id\s*\(`,
			ObjectType:  "Entity",
			MethodName:  "find_by_id",
			Description: "SeaORM entity lookup by primary key from database",
			Assigns:     "return",
		},

		// --- External data sources (SrcExternal) ---

		// Redis data retrieval
		{
			ID:          "rust.redis.cmd",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `redis::cmd\s*\(`,
			ObjectType:  "redis",
			MethodName:  "redis::cmd",
			Description: "Redis command — data from untrusted shared store",
			Assigns:     "return",
		},

		// redis-rs Commands / AsyncCommands trait read methods.
		// Return values are attacker-controllable when an upstream writer can
		// store arbitrary data into the shared cache (second-order taint).
		// All method names below are unique to the Redis API and won't collide
		// with stdlib methods like Vec::pop or HashMap::get.
		{
			ID:          "rust.redis.hgetall",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.hgetall\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "hgetall",
			Description: "redis-rs HGETALL — entire hash from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.hkeys",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.hkeys\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "hkeys",
			Description: "redis-rs HKEYS — hash field names from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.hvals",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.hvals\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "hvals",
			Description: "redis-rs HVALS — hash values from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.hmget",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.hmget\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "hmget",
			Description: "redis-rs HMGET — multiple hash fields from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.mget",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.mget\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "mget",
			Description: "redis-rs MGET — multiple keys from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.lrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.lrange\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "lrange",
			Description: "redis-rs LRANGE — list range from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.lindex",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.lindex\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "lindex",
			Description: "redis-rs LINDEX — list element by index from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.lpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.lpop\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "lpop",
			Description: "redis-rs LPOP — pop from list head in shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.rpop",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.rpop\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "rpop",
			Description: "redis-rs RPOP — pop from list tail in shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.smembers",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.smembers\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "smembers",
			Description: "redis-rs SMEMBERS — entire set from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.srandmember",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.srandmember\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "srandmember",
			Description: "redis-rs SRANDMEMBER — random set member from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.spop",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.spop\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "spop",
			Description: "redis-rs SPOP — pop set member from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.zrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.zrange\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "zrange",
			Description: "redis-rs ZRANGE — sorted-set range from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.zrevrange",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.zrevrange\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "zrevrange",
			Description: "redis-rs ZREVRANGE — reverse sorted-set range from shared cache (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.redis.zrangebyscore",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.zrangebyscore\s*\(`,
			ObjectType:  "redis::Connection",
			MethodName:  "zrangebyscore",
			Description: "redis-rs ZRANGEBYSCORE — sorted-set range by score from shared cache (untrusted)",
			Assigns:     "return",
		},

		// --- Cassandra / ScyllaDB read sources (second-order taint) ---
		// Data persisted to Cassandra/ScyllaDB by any writer — including an
		// attacker in an earlier request — is untrusted when read back and
		// reaches a downstream sink (CQL/SQL injection, command exec, etc.).
		// This mirrors the Java (DataStax) and Kotlin Cassandra Row read-source
		// cycles. The matching write-side CQL-injection sinks already exist in
		// rust_sinks.go (rust.scylla.session.* / rust.cdrs_tokio.session.*).
		//
		// All method names below are unique to the scylla / cdrs-tokio result
		// APIs and do not collide with stdlib (Vec/HashMap) methods, so
		// ObjectType is left empty and matching relies on the method name. The
		// `*_typed` / `rows_typed*` variants are turbofish method calls
		// (`result.first_row_typed::<T>()`), matched via the rustConfig
		// generic_function unwrap.

		// scylla crate — QueryResult / QueryRowsResult row extraction
		{
			ID:          "rust.scylla.first_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.first_row\s*\(`,
			ObjectType:  "",
			MethodName:  "first_row",
			Description: "scylla QueryResult::first_row — first CQL result row from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.first_row_typed",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.first_row_typed\s*`,
			ObjectType:  "",
			MethodName:  "first_row_typed",
			Description: "scylla QueryResult::first_row_typed — typed first CQL row from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.single_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.single_row\s*\(`,
			ObjectType:  "",
			MethodName:  "single_row",
			Description: "scylla QueryResult::single_row — single CQL result row from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.single_row_typed",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.single_row_typed\s*`,
			ObjectType:  "",
			MethodName:  "single_row_typed",
			Description: "scylla QueryResult::single_row_typed — typed single CQL row from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.maybe_first_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.maybe_first_row\s*\(`,
			ObjectType:  "",
			MethodName:  "maybe_first_row",
			Description: "scylla QueryResult::maybe_first_row — optional first CQL row from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.maybe_first_row_typed",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.maybe_first_row_typed\s*`,
			ObjectType:  "",
			MethodName:  "maybe_first_row_typed",
			Description: "scylla QueryResult::maybe_first_row_typed — typed optional first CQL row from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.rows_typed",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.rows_typed\s*`,
			ObjectType:  "",
			MethodName:  "rows_typed",
			Description: "scylla QueryResult::rows_typed — typed CQL result rows from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.scylla.rows_typed_or_empty",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.rows_typed_or_empty\s*`,
			ObjectType:  "",
			MethodName:  "rows_typed_or_empty",
			Description: "scylla QueryResult::rows_typed_or_empty — typed CQL result rows from Cassandra/ScyllaDB (untrusted)",
			Assigns:     "return",
		},
		// cdrs-tokio crate — Row column extraction
		{
			ID:          "rust.cdrs_tokio.row.get_by_name",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.get_by_name\s*\(`,
			ObjectType:  "",
			MethodName:  "get_by_name",
			Description: "cdrs-tokio Row::get_by_name — CQL column value by name from Cassandra (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.cdrs_tokio.row.get_r_by_name",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.get_r_by_name\s*\(`,
			ObjectType:  "",
			MethodName:  "get_r_by_name",
			Description: "cdrs-tokio Row::get_r_by_name — required CQL column value by name from Cassandra (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.cdrs_tokio.row.get_by_index",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.get_by_index\s*\(`,
			ObjectType:  "",
			MethodName:  "get_by_index",
			Description: "cdrs-tokio Row::get_by_index — CQL column value by index from Cassandra (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.cdrs_tokio.row.get_r_by_index",
			Category:    taint.SrcDatabase,
			Language:    rules.LangRust,
			Pattern:     `\.get_r_by_index\s*\(`,
			ObjectType:  "",
			MethodName:  "get_r_by_index",
			Description: "cdrs-tokio Row::get_r_by_index — required CQL column value by index from Cassandra (untrusted)",
			Assigns:     "return",
		},

		// --- Kafka (rdkafka crate) ---
		{
			ID:          "rust.rdkafka.consumer.recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `consumer\.recv\s*\(`,
			ObjectType:  "",
			MethodName:  "recv",
			Description: "rdkafka StreamConsumer recv — message from Kafka broker (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.rdkafka.payload",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.payload\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "payload",
			Description: "rdkafka Message payload bytes — raw Kafka message content (untrusted)",
			Assigns:     "return",
		},

		// --- tokio async channels (tokio::sync::{mpsc,broadcast,oneshot,watch}) ---
		//
		// Channels are the primary way tainted data crosses an async-task
		// boundary in tokio programs: an HTTP/WS handler (or any ingest task)
		// receives attacker-controlled bytes and forwards them over a channel
		// to a worker task that reaches the dangerous sink. The producer→sink
		// flow is split across two tasks/functions, so without modeling the
		// receiving end the worker's `rx.recv().await` looks like clean data and
		// the injection is silently dropped. We treat the value yielded by a
		// channel receiver as untrusted (SrcExternal): the consumer cannot, in
		// general, know the producer only ever sends safe data, and the
		// conservative assumption matches how an attacker reaches the sink.
		//
		// These method names (recv/try_recv/blocking_recv/recv_many/
		// borrow_and_update) are distinctive to the tokio channel receiver
		// surface, so an empty ObjectType (match any receiver) does not collide
		// with unrelated Rust APIs. The bare `borrow()` method is intentionally
		// NOT modeled here — it is the std Borrow/RefCell trait method and would
		// over-taint; `borrow_and_update()` is watch-specific and safe.
		{
			ID:          "rust.tokio.mpsc.recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.recv\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "recv",
			Description: "tokio::sync::mpsc/broadcast Receiver::recv — value received from an async channel; the sending task may forward attacker-controlled data across the task boundary (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tokio.mpsc.try_recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.try_recv\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "try_recv",
			Description: "tokio::sync::mpsc/broadcast Receiver::try_recv — non-blocking channel receive; carries attacker-controlled data forwarded by the sending task (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tokio.mpsc.blocking_recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.blocking_recv\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "blocking_recv",
			Description: "tokio::sync::mpsc/broadcast Receiver::blocking_recv — synchronous channel receive from a blocking context; carries attacker-controlled data across the task boundary (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tokio.mpsc.recv_many",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.recv_many\s*\(`,
			ObjectType:  "",
			MethodName:  "recv_many",
			Description: "tokio::sync::mpsc Receiver::recv_many — batch channel receive; the destination buffer is filled with attacker-controlled data forwarded by the sending task (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tokio.watch.borrow_and_update",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.borrow_and_update\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "borrow_and_update",
			Description: "tokio::sync::watch Receiver::borrow_and_update — reads the latest broadcast value; the producing task may publish attacker-controlled data across the task boundary (untrusted)",
			Assigns:     "return",
		},

		// --- RabbitMQ (lapin crate) ---
		{
			ID:          "rust.lapin.basic_consume",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.basic_consume\s*\(`,
			ObjectType:  "Channel",
			MethodName:  "basic_consume",
			Description: "lapin RabbitMQ consumer setup — messages from AMQP broker (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.lapin.delivery.data",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `delivery\.data\b`,
			ObjectType:  "Delivery",
			MethodName:  "data",
			Description: "lapin Delivery payload bytes — RabbitMQ message body (untrusted)",
			Assigns:     "return",
		},

		// --- gRPC (tonic crate) ---
		{
			ID:          "rust.tonic.request.into_inner",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `request\.into_inner\s*\(`,
			ObjectType:  "Request",
			MethodName:  "into_inner",
			Description: "tonic Request::into_inner — gRPC request payload extraction (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tonic.request.get_ref",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `request\.get_ref\s*\(`,
			ObjectType:  "Request",
			MethodName:  "get_ref",
			Description: "tonic Request::get_ref — gRPC request payload borrow (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tonic.request.metadata",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `request\.metadata\s*\(`,
			ObjectType:  "Request",
			MethodName:  "metadata",
			Description: "tonic Request metadata — gRPC headers/metadata (untrusted)",
			Assigns:     "return",
		},

		// --- NATS (async-nats crate) ---
		{
			ID:          "rust.nats.subscribe",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `client\.subscribe\s*\(`,
			ObjectType:  "Client",
			MethodName:  "subscribe",
			Description: "async-nats subscribe — NATS message stream (untrusted)",
			Assigns:     "return",
		},

		// --- MQTT (rumqttc crate) ---
		{
			ID:          "rust.rumqttc.eventloop.poll",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `eventloop\.poll\s*\(`,
			ObjectType:  "EventLoop",
			MethodName:  "poll",
			Description: "rumqttc EventLoop poll — MQTT event from broker (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.rumqttc.incoming.publish",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `Incoming::Publish\s*\(`,
			ObjectType:  "Incoming",
			MethodName:  "Publish",
			Description: "rumqttc Incoming::Publish — MQTT publish event with payload (untrusted)",
			Assigns:     "return",
		},

		// --- Apache Pulsar (pulsar crate) ---
		{
			ID:          "rust.pulsar.consumer.try_next",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `consumer\.try_next\s*\(`,
			ObjectType:  "Consumer",
			MethodName:  "try_next",
			Description: "Pulsar consumer try_next — message from Pulsar broker (untrusted)",
			Assigns:     "return",
		},

		// --- Archive extraction entry names (Zip Slip / Tar Slip — CWE-22) ---
		// Entry names come from the archive header and are fully attacker-controlled
		// (e.g., "../../etc/passwd"). When used in a path-handling sink without
		// enclosed_name / normalization, this yields arbitrary file overwrite.
		{
			ID:          "rust.zip.file.mangled_name",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.mangled_name\s*\(`,
			ObjectType:  "",
			MethodName:  "mangled_name",
			Description: "zip crate ZipFile::mangled_name — raw entry path from untrusted archive (Zip Slip)",
			Assigns:     "return",
		},
		{
			ID:          "rust.zip.archive.file_names",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.file_names\s*\(`,
			ObjectType:  "",
			MethodName:  "file_names",
			Description: "zip crate ZipArchive::file_names — entry names from untrusted archive (Zip Slip)",
			Assigns:     "return",
		},
		{
			ID:          "rust.tar.entry.path_bytes",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.path_bytes\s*\(`,
			ObjectType:  "",
			MethodName:  "path_bytes",
			Description: "tar crate Entry/Header::path_bytes — raw entry path bytes from untrusted archive (Tar Slip)",
			Assigns:     "return",
		},

		// --- GraphQL resolver sources — async-graphql + juniper (CWE-74 / CWE-89 / CWE-78) ---
		// async-graphql resolvers receive `ctx: &Context<'_>` and juniper's
		// lower-level resolvers receive `executor: &Executor<...>`. Both
		// expose client-supplied field arguments, operation variables, and
		// selection state. Values pulled through these methods are fully
		// attacker-controlled and flow straight into whatever sink the
		// resolver calls next (SQL, shell, templates, URL fetches, etc.).
		// Method names are intentionally distinctive — `param_value` /
		// `oneof_param_value` are async-graphql-only; `look_ahead` is
		// shared between async-graphql and juniper.
		{
			ID:          "rust.async_graphql.ctx.param_value",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\bctx\.param_value\s*[:(]`,
			ObjectType:  "",
			MethodName:  "param_value",
			Description: "async-graphql Context::param_value — named resolver field argument from client query",
			Assigns:     "return",
		},
		{
			ID:          "rust.async_graphql.ctx.oneof_param_value",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\bctx\.oneof_param_value\s*[:(]`,
			ObjectType:  "",
			MethodName:  "oneof_param_value",
			Description: "async-graphql Context::oneof_param_value — OneofObject resolver argument from client query",
			Assigns:     "return",
		},
		{
			ID:          "rust.graphql.look_ahead",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\b(?:ctx|executor)\.look_ahead\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "look_ahead",
			Description: "GraphQL resolver look_ahead — selection over client's query document (async-graphql Context or juniper Executor)",
			Assigns:     "return",
		},
		{
			ID:          "rust.juniper.executor.variables",
			Category:    taint.SrcUserInput,
			Language:    rules.LangRust,
			Pattern:     `\bexecutor\.variables\s*\(\s*\)`,
			ObjectType:  "",
			MethodName:  "variables",
			Description: "juniper Executor::variables — raw operation variables map submitted with the GraphQL request",
			Assigns:     "return",
		},

		// --- HTTP client response bodies (SrcExternal) ---
		// Response bodies fetched via HTTP clients are attacker-controlled when the
		// URL is user-supplied (SSRF chain) or the remote endpoint is otherwise
		// untrusted. Common downstream chains: SSRF → render response → stored XSS;
		// link-unfurl/proxy services → HTML/template injection; OAuth callback
		// handlers that echo upstream errors. Receiver naming convention in real
		// Rust code: `response`, `resp`, `r` — all match ObjectType "Response" via
		// the lastPart prefix-abbrev heuristic in matcher.go.
		{
			ID:          "rust.reqwest.response.text",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.text\s*\(\s*\)\s*\.\s*await`,
			ObjectType:  "Response",
			MethodName:  "text",
			Description: "reqwest Response::text — async response body as String (untrusted external content)",
			Assigns:     "return",
		},
		{
			ID:          "rust.reqwest.response.text_with_charset",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.text_with_charset\s*\(`,
			ObjectType:  "Response",
			MethodName:  "text_with_charset",
			Description: "reqwest Response::text_with_charset — async body decoded with explicit charset (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.reqwest.response.json",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.json\s*(?:::\s*<[^>]+>)?\s*\(\s*\)\s*\.\s*await`,
			ObjectType:  "Response",
			MethodName:  "json",
			Description: "reqwest Response::json — async deserialized response body (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.reqwest.response.bytes",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.bytes\s*\(\s*\)\s*\.\s*await`,
			ObjectType:  "Response",
			MethodName:  "bytes",
			Description: "reqwest Response::bytes — async raw response body bytes (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.reqwest.response.bytes_stream",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.bytes_stream\s*\(`,
			ObjectType:  "Response",
			MethodName:  "bytes_stream",
			Description: "reqwest Response::bytes_stream — streaming response body chunks (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.reqwest.response.chunk",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.chunk\s*\(\s*\)\s*\.\s*await`,
			ObjectType:  "Response",
			MethodName:  "chunk",
			Description: "reqwest Response::chunk — single streaming chunk from response body (untrusted)",
			Assigns:     "return",
		},
		{
			ID:          "rust.ureq.response.into_string",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.into_string\s*\(`,
			ObjectType:  "Response",
			MethodName:  "into_string",
			Description: "ureq Response::into_string — sync response body as String (untrusted external content)",
			Assigns:     "return",
		},
		{
			ID:          "rust.ureq.response.into_reader",
			Category:    taint.SrcExternal,
			Language:    rules.LangRust,
			Pattern:     `\.into_reader\s*\(`,
			ObjectType:  "Response",
			MethodName:  "into_reader",
			Description: "ureq Response::into_reader — sync response body as Read implementation (untrusted)",
			Assigns:     "return",
		},

		// --- Additional Rust web-framework request sources ---
		// actix-web extractors and HttpRequest accessors
		{ID: "rust.actix.json", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `web::Json\s*<`, ObjectType: "actix_web", MethodName: "web::Json", Description: "actix-web Json<T> extractor — deserialised JSON body from request", Assigns: "return"},
		{ID: "rust.actix.form", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `web::Form\s*<`, ObjectType: "actix_web", MethodName: "web::Form", Description: "actix-web Form<T> extractor — url-encoded form body", Assigns: "return"},
		{ID: "rust.actix.bytes", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `web::Bytes\b`, ObjectType: "actix_web", MethodName: "web::Bytes", Description: "actix-web Bytes extractor — raw request body bytes", Assigns: "return"},
		{ID: "rust.actix.payload", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `web::Payload\b`, ObjectType: "actix_web", MethodName: "web::Payload", Description: "actix-web Payload extractor — streaming raw request body", Assigns: "return"},
		{ID: "rust.actix.httprequest.headers", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\.headers\s*\(\s*\)`, ObjectType: "actix_web::HttpRequest", MethodName: "headers", Description: "actix-web HttpRequest::headers — request headers", Assigns: "return"},
		{ID: "rust.actix.httprequest.cookie", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\.cookie\s*\(`, ObjectType: "actix_web::HttpRequest", MethodName: "cookie", Description: "actix-web HttpRequest::cookie — request cookie by name", Assigns: "return"},
		{ID: "rust.actix.httprequest.uri", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\.uri\s*\(\s*\)`, ObjectType: "actix_web::HttpRequest", MethodName: "uri", Description: "actix-web HttpRequest::uri — request URI (path + query)", Assigns: "return"},
		{ID: "rust.actix.httprequest.connection_info", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\.connection_info\s*\(\s*\)`, ObjectType: "actix_web::HttpRequest", MethodName: "connection_info", Description: "actix-web HttpRequest::connection_info — client IP and host (X-Forwarded-For spoofable)", Assigns: "return"},

		// axum extractors
		{ID: "rust.axum.json", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bJson\s*<`, ObjectType: "axum::extract::Json", MethodName: "Json", Description: "axum Json<T> extractor — deserialised request body", Assigns: "return"},
		{ID: "rust.axum.form", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bForm\s*<`, ObjectType: "axum::extract::Form", MethodName: "Form", Description: "axum Form<T> extractor — url-encoded body", Assigns: "return"},
		{ID: "rust.axum.query", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bQuery\s*<`, ObjectType: "axum::extract::Query", MethodName: "Query", Description: "axum Query<T> extractor — URL query params", Assigns: "return"},
		{ID: "rust.axum.path", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bPath\s*<`, ObjectType: "axum::extract::Path", MethodName: "Path", Description: "axum Path<T> extractor — URL path segments", Assigns: "return"},
		{ID: "rust.axum.bytes", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bBytes\b`, ObjectType: "axum::body::Bytes", MethodName: "Bytes", Description: "axum Bytes extractor — raw body bytes", Assigns: "return"},
		{ID: "rust.axum.headermap", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bHeaderMap\b`, ObjectType: "axum::http::HeaderMap", MethodName: "HeaderMap", Description: "axum HeaderMap extractor — request headers", Assigns: "return"},
		{ID: "rust.axum.typedheader", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bTypedHeader\s*<`, ObjectType: "axum::extract::TypedHeader", MethodName: "TypedHeader", Description: "axum TypedHeader<T> extractor — single typed header", Assigns: "return"},

		// rocket extractors
		{ID: "rust.rocket.formdata", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bForm\s*<`, ObjectType: "rocket::form::Form", MethodName: "Form", Description: "rocket Form<T> guard — url-encoded form body", Assigns: "return"},
		{ID: "rust.rocket.json", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\bJson\s*<`, ObjectType: "rocket_contrib::json::Json", MethodName: "Json", Description: "rocket Json<T> guard — JSON request body", Assigns: "return"},
		{ID: "rust.rocket.request.headers", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `\.headers\s*\(\s*\)`, ObjectType: "rocket::Request", MethodName: "headers", Description: "rocket Request::headers — header collection", Assigns: "return"},

		// warp filter combinators
		{ID: "rust.warp.query_filter", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `warp::query\s*\(\s*\)|warp::query::<`, ObjectType: "warp::filters::query", MethodName: "query", Description: "warp query filter — deserialised query params", Assigns: "return"},
		{ID: "rust.warp.body_json", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `warp::body::json\s*\(\s*\)`, ObjectType: "warp::filters::body", MethodName: "json", Description: "warp body::json filter — deserialised JSON body", Assigns: "return"},
		{ID: "rust.warp.body_form", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `warp::body::form\s*\(\s*\)`, ObjectType: "warp::filters::body", MethodName: "form", Description: "warp body::form filter — url-encoded form body", Assigns: "return"},
		{ID: "rust.warp.header", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `warp::header\s*::`, ObjectType: "warp::filters::header", MethodName: "header", Description: "warp header filter — specific request header", Assigns: "return"},
		{ID: "rust.warp.path_param", Category: taint.SrcUserInput, Language: rules.LangRust, Pattern: `warp::path::param\s*\(\s*\)`, ObjectType: "warp::filters::path", MethodName: "path::param", Description: "warp path::param filter — URL path segment", Assigns: "return"},

		// --- Network sources — outbound HTTP / WS / DNS responses ---
		{ID: "rust.reqwest.text", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `\.text\s*\(\s*\)\.await`, ObjectType: "reqwest::Response", MethodName: "text", Description: "reqwest Response.text() — body of an outbound HTTP response (server-attacker-controlled bytes)", Assigns: "return"},
		{ID: "rust.reqwest.bytes", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `\.bytes\s*\(\s*\)\.await`, ObjectType: "reqwest::Response", MethodName: "bytes", Description: "reqwest Response.bytes() — raw response body", Assigns: "return"},
		{ID: "rust.reqwest.json", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `\.json::<[^>]+>\s*\(\s*\)\.await`, ObjectType: "reqwest::Response", MethodName: "json::<T>", Description: "reqwest Response.json::<T>() — deserialised JSON body of an outbound HTTP response", Assigns: "return"},
		{ID: "rust.hyper.body_to_bytes", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `hyper::body::to_bytes\s*\(|hyper::body::aggregate\s*\(`, ObjectType: "hyper::body", MethodName: "to_bytes/aggregate", Description: "hyper to_bytes / aggregate — buffered body of an outbound or inbound HTTP message", Assigns: "return"},
		{ID: "rust.surf.body_string", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `\.body_string\s*\(\s*\)\.await|\.body_json\s*\(\s*\)\.await`, ObjectType: "surf::Response", MethodName: "body_string/body_json", Description: "surf Response.body_string / body_json — outbound HTTP response body", Assigns: "return"},
		{ID: "rust.tokio_tungstenite.read_message", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `tokio_tungstenite.*\.next\s*\(\s*\)|tungstenite::Message::Text\b`, ObjectType: "tokio_tungstenite::WebSocketStream", MethodName: "read_message", Description: "tokio-tungstenite WebSocketStream — WS frame from a remote peer", Assigns: "return"},
		{ID: "rust.trust_dns.lookup", Category: taint.SrcNetwork, Language: rules.LangRust, Pattern: `trust_dns_resolver::.*::lookup\s*\(|\.lookup_ip\s*\(`, ObjectType: "trust_dns_resolver::AsyncResolver", MethodName: "lookup/lookup_ip", Description: "trust-dns AsyncResolver.lookup / lookup_ip — DNS-server-controlled response data", Assigns: "return"},
	}
}
