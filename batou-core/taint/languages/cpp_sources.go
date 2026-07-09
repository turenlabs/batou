package languages

import (
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func (cppCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// ── iostream / stdin ──────────────────────────────────────────
		{ID: "cpp.cin.extraction", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `std::cin\s*>>`, ObjectType: "std::istream", MethodName: "operator>>", Description: "std::cin extraction operator reads user input", Assigns: "return"},
		{ID: "cpp.getline.cin", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `std::getline\s*\(\s*(?:std::)?cin`, ObjectType: "std", MethodName: "getline", Description: "std::getline reading from cin", Assigns: "return"},
		{ID: "cpp.getline.stream", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `std::getline\s*\(`, ObjectType: "std", MethodName: "getline", Description: "std::getline reading from a stream", Assigns: "return"},

		// ── C-inherited sources ──────────────────────────────────────
		{ID: "cpp.cstdio.scanf", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\bscanf\s*\(`, ObjectType: "", MethodName: "scanf", Description: "scanf reads formatted user input from stdin", Assigns: "arg:1"},
		{ID: "cpp.cstdio.gets", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\bgets\s*\(`, ObjectType: "", MethodName: "gets", Description: "gets reads a line from stdin (unsafe, removed in C11)", Assigns: "arg:0"},
		{ID: "cpp.cstdio.fgets", Category: taint.SrcFileRead, Language: rules.LangCPP, Pattern: `\bfgets\s*\(`, ObjectType: "", MethodName: "fgets", Description: "fgets reads from a file stream", Assigns: "arg:0"},
		{ID: "cpp.cstdio.fread", Category: taint.SrcFileRead, Language: rules.LangCPP, Pattern: `\bfread\s*\(`, ObjectType: "", MethodName: "fread", Description: "fread reads binary data from a file stream", Assigns: "arg:0"},
		{ID: "cpp.cstdlib.getenv", Category: taint.SrcEnvVar, Language: rules.LangCPP, Pattern: `\bgetenv\s*\(`, ObjectType: "", MethodName: "getenv", Description: "getenv reads an environment variable", Assigns: "return"},
		{ID: "cpp.unistd.read", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `\bread\s*\(\s*\w+\s*,`, ObjectType: "", MethodName: "read", Description: "POSIX read from file descriptor (network/file)", Assigns: "arg:1"},
		{ID: "cpp.socket.recv", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `\brecv\s*\(`, ObjectType: "", MethodName: "recv", Description: "Socket recv reads network data", Assigns: "arg:1"},
		{ID: "cpp.socket.recvfrom", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `\brecvfrom\s*\(`, ObjectType: "", MethodName: "recvfrom", Description: "Socket recvfrom reads network data with source address", Assigns: "arg:1"},
		{ID: "cpp.main.argv", Category: taint.SrcCLIArg, Language: rules.LangCPP, Pattern: `\bargv\s*\[`, ObjectType: "", MethodName: "argv", Description: "Command-line arguments", Assigns: "return"},
		{ID: "cpp.cstdio.fscanf", Category: taint.SrcFileRead, Language: rules.LangCPP, Pattern: `\bfscanf\s*\(`, ObjectType: "", MethodName: "fscanf", Description: "fscanf reads formatted input from a file stream", Assigns: "arg:2"},
		{ID: "cpp.cstdio.sscanf", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\bsscanf\s*\(`, ObjectType: "", MethodName: "sscanf", Description: "sscanf parses formatted data from a string", Assigns: "arg:2"},
		{ID: "cpp.cstdio.getchar", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\bgetchar\s*\(\s*\)`, ObjectType: "", MethodName: "getchar", Description: "getchar reads a single character from stdin", Assigns: "return"},
		{ID: "cpp.cstdio.fgetc", Category: taint.SrcFileRead, Language: rules.LangCPP, Pattern: `\bfgetc\s*\(`, ObjectType: "", MethodName: "fgetc", Description: "fgetc reads a single character from a file stream", Assigns: "return"},
		{ID: "cpp.socket.recvmsg", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `\brecvmsg\s*\(`, ObjectType: "", MethodName: "recvmsg", Description: "Socket recvmsg reads network message data", Assigns: "arg:1"},
		{ID: "cpp.gnu.getline", Category: taint.SrcFileRead, Language: rules.LangCPP, Pattern: `\bgetline\s*\(\s*&`, ObjectType: "", MethodName: "getline (C/POSIX)", Description: "POSIX/GNU getline reads a line from a stream", Assigns: "arg:0"},

		// ── C++ web framework sources (Crow) ─────────────────────────
		{ID: "cpp.crow.request.url_params", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.url_params\.get\s*\(`, ObjectType: "crow::request", MethodName: "url_params.get", Description: "Crow HTTP request URL parameter", Assigns: "return"},
		{ID: "cpp.crow.request.body", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.body`, ObjectType: "crow::request", MethodName: "body", Description: "Crow HTTP request body", Assigns: "return"},
		{ID: "cpp.crow.request.url", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.url`, ObjectType: "crow::request", MethodName: "url", Description: "Crow HTTP request URL", Assigns: "return"},
		{ID: "cpp.crow.request.get_header", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.get_header_value\s*\(`, ObjectType: "crow::request", MethodName: "get_header_value", Description: "Crow HTTP request header value", Assigns: "return"},

		// ── C++ web framework sources (Pistache) ─────────────────────
		{ID: "cpp.pistache.request.body", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `request\.body\s*\(\s*\)`, ObjectType: "Pistache::Http::Request", MethodName: "body", Description: "Pistache HTTP request body", Assigns: "return"},
		{ID: "cpp.pistache.request.query", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `request\.query\s*\(\s*\)`, ObjectType: "Pistache::Http::Request", MethodName: "query", Description: "Pistache HTTP request query", Assigns: "return"},
		{ID: "cpp.pistache.request.param", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `request\.param\s*\(`, ObjectType: "Pistache::Http::Request", MethodName: "param", Description: "Pistache HTTP request parameter", Assigns: "return"},

		// ── C++ web framework sources (cpp-httplib) ──────────────────
		{ID: "cpp.httplib.request.body", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.body`, ObjectType: "httplib::Request", MethodName: "body", Description: "cpp-httplib request body", Assigns: "return"},
		{ID: "cpp.httplib.request.get_param", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.get_param_value\s*\(`, ObjectType: "httplib::Request", MethodName: "get_param_value", Description: "cpp-httplib request parameter", Assigns: "return"},
		{ID: "cpp.httplib.request.get_header", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req\.get_header_value\s*\(`, ObjectType: "httplib::Request", MethodName: "get_header_value", Description: "cpp-httplib request header", Assigns: "return"},

		// ── Qt sources ───────────────────────────────────────────────
		{ID: "cpp.qt.qurl", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `QUrl\s*\(`, ObjectType: "QUrl", MethodName: "QUrl", Description: "Qt URL construction from user input", Assigns: "return"},
		{ID: "cpp.qt.qnetworkreply.readall", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `(?:QNetworkReply|reply)\s*->\s*readAll\s*\(\s*\)`, ObjectType: "QNetworkReply", MethodName: "readAll", Description: "Qt network reply data", Assigns: "return"},
		{ID: "cpp.qt.qlineedit.text", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `(?:QLineEdit|lineEdit)\s*->\s*text\s*\(\s*\)`, ObjectType: "QLineEdit", MethodName: "text", Description: "Qt line edit user text input", Assigns: "return"},
		{ID: "cpp.qt.qtextedit.toplaintext", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `(?:QTextEdit|textEdit)\s*->\s*toPlainText\s*\(\s*\)`, ObjectType: "QTextEdit", MethodName: "toPlainText", Description: "Qt text edit user input", Assigns: "return"},

		// ── Boost.Asio sources ────────────────────────────────────────
		{ID: "cpp.boost.asio.read", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `boost::asio::read\s*\(`, ObjectType: "boost::asio", MethodName: "read", Description: "Boost.Asio socket read", Assigns: "arg:1"},
		{ID: "cpp.boost.asio.async_read", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `boost::asio::async_read\s*\(`, ObjectType: "boost::asio", MethodName: "async_read", Description: "Boost.Asio async socket read", Assigns: "arg:1"},
		{ID: "cpp.boost.asio.read_some", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `\.read_some\s*\(`, ObjectType: "boost::asio::ip::tcp::socket", MethodName: "read_some", Description: "Boost.Asio socket read_some", Assigns: "arg:0"},
		{ID: "cpp.boost.asio.read_until", Category: taint.SrcNetwork, Language: rules.LangCPP, Pattern: `boost::asio::read_until\s*\(`, ObjectType: "boost::asio", MethodName: "read_until", Description: "Boost.Asio read until delimiter from socket", Assigns: "arg:1"},

		// ── Boost.Beast HTTP sources ──────────────────────────────────
		{ID: "cpp.boost.beast.http.request.body", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `(?:request|req)\.body\s*\(\s*\)`, ObjectType: "boost::beast::http::request", MethodName: "body", Description: "Boost.Beast HTTP request body", Assigns: "return"},
		{ID: "cpp.boost.beast.http.request.target", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `(?:request|req)\.target\s*\(\s*\)`, ObjectType: "boost::beast::http::request", MethodName: "target", Description: "Boost.Beast HTTP request target/URL", Assigns: "return"},

		// ── File stream sources ───────────────────────────────────────
		{ID: "cpp.ifstream.read", Category: taint.SrcFileRead, Language: rules.LangCPP, Pattern: `(?:std::)?ifstream.*>>|\.read\s*\(`, ObjectType: "std::ifstream", MethodName: "read/>>", Description: "File input stream reading", Assigns: "return"},

		// ── Deserialization sources ────────────────────────────────────
		{ID: "cpp.boost.serialization", Category: taint.SrcDeserialized, Language: rules.LangCPP, Pattern: `boost::archive::\w+_iarchive`, ObjectType: "boost::archive", MethodName: "input_archive", Description: "Boost.Serialization deserialized data", Assigns: "return"},
		{ID: "cpp.protobuf.parsefromstring", Category: taint.SrcDeserialized, Language: rules.LangCPP, Pattern: `\.ParseFromString\s*\(|\.ParseFromArray\s*\(`, ObjectType: "google::protobuf::Message", MethodName: "ParseFromString", Description: "Protocol Buffers deserialized data", Assigns: "return"},

		// ── Boost.Beast HTTP header sources ───────────────────────────
		{ID: "cpp.boost.beast.http.request.header", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `(?:request|req)\[http::field::\w+\]|(?:request|req)\.at\s*\(\s*http::field::`, ObjectType: "boost::beast::http::request", MethodName: "header_field", Description: "Boost.Beast HTTP request header field", Assigns: "return"},

		// ── Drogon HTTP sources ───────────────────────────────────────
		{ID: "cpp.drogon.request.input", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `req->(?:getParameter|getBody|getCookie|getHeader)\s*\(`, ObjectType: "drogon::HttpRequest", MethodName: "getParameter/getBody/getCookie/getHeader", Description: "Drogon HTTP request input", Assigns: "return"},

		// ── POCO HTTP sources ────────────────────────────────────────
		{ID: "cpp.poco.httpserverrequest.input", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `request\.(?:get|getURI|getHost)\s*\(`, ObjectType: "Poco::Net::HTTPServerRequest", MethodName: "get/getURI/getHost", Description: "POCO HTTP server request input", Assigns: "return"},

		// --- Additional framework sources ---
		{
			ID:          "cpp.grpc.request",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCPP,
			Pattern:     `grpc::ServerContext|::grpc::ServerReader`,
			ObjectType:  "grpc::ServerContext",
			MethodName:  "ServerContext",
			Description: "gRPC server request data",
			Assigns:     "return",
		},
		{
			ID:          "cpp.websocketpp.message",
			Category:    taint.SrcNetwork,
			Language:    rules.LangCPP,
			Pattern:     `websocketpp::.*::message_ptr|msg->get_payload\s*\(`,
			ObjectType:  "websocketpp",
			MethodName:  "get_payload",
			Description: "WebSocket++ message payload",
			Assigns:     "return",
		},
		{
			ID:          "cpp.nlohmann.json.parse",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCPP,
			Pattern:     `nlohmann::json::parse\s*\(|json::parse\s*\(`,
			ObjectType:  "nlohmann::json",
			MethodName:  "parse",
			Description: "nlohmann JSON parsed from potentially untrusted data",
			Assigns:     "return",
		},
		{
			ID:          "cpp.rapidjson.parse",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCPP,
			Pattern:     `rapidjson::Document.*\.Parse\s*\(`,
			ObjectType:  "rapidjson::Document",
			MethodName:  "Parse",
			Description: "RapidJSON parsed from potentially untrusted data",
			Assigns:     "return",
		},
		{
			ID:          "cpp.civetweb.request",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `mg_get_request_info\s*\(|mg_read\s*\(`,
			ObjectType:  "civetweb",
			MethodName:  "mg_get_request_info/mg_read",
			Description: "CivetWeb/Mongoose HTTP request data",
			Assigns:     "return",
		},

		// ── Database result sources (SrcDatabase) ────────────────────
		{
			ID:          "cpp.sqlite3.column_text",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bsqlite3_column_text\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_text",
			Description: "SQLite column text result (stored XSS/second-order injection vector)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.sqlite3.column_blob",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bsqlite3_column_blob\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_blob",
			Description: "SQLite column blob result (untrusted binary data from DB)",
			Assigns:     "return",
		},
		// Numeric SQLite column readers complete the sqlite3_column_* family
		// (text/blob already modelled above). Like the cpp.mysql.connector
		// ResultSet::getInt/getInt64/getDouble readers, these return values
		// that were stored in the database — attacker-controlled if an earlier
		// write path did not validate them (second-order taint, e.g. a numeric
		// value formatted back into a query / command / file path). Free
		// functions with library-unique names, so ObjectType is "".
		{
			ID:          "cpp.sqlite3.column_int",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bsqlite3_column_int\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_int",
			Description: "SQLite column int result (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.sqlite3.column_int64",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bsqlite3_column_int64\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_int64",
			Description: "SQLite column int64 result (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.sqlite3.column_double",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bsqlite3_column_double\s*\(`,
			ObjectType:  "",
			MethodName:  "sqlite3_column_double",
			Description: "SQLite column double result (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mysql.fetch_row",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bmysql_fetch_row\s*\(`,
			ObjectType:  "",
			MethodName:  "mysql_fetch_row",
			Description: "MySQL fetch row result (stored data may be tainted)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.pq.getvalue",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bPQgetvalue\s*\(`,
			ObjectType:  "",
			MethodName:  "PQgetvalue",
			Description: "PostgreSQL PQgetvalue result (stored data may be tainted)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.qt.qsqlquery.value",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:QSqlQuery|query)\s*\.\s*value\s*\(`,
			ObjectType:  "QSqlQuery",
			MethodName:  "value",
			Description: "Qt SQL query result value (stored data may be tainted)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.soci.into",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `soci::into\s*\(`,
			ObjectType:  "",
			MethodName:  "into",
			Description: "SOCI into() binds query result to variable (stored data may be tainted)",
			Assigns:     "arg:0",
		},
		{
			ID:          "cpp.nanodbc.result.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:nanodbc::result|result)\s*\.\s*get\s*<`,
			ObjectType:  "nanodbc::result",
			MethodName:  "get<T>",
			Description: "nanodbc result get (stored data may be tainted)",
			Assigns:     "return",
		},

		// ── Drogon extended sources ──────────────────────────────────
		{
			ID:          "cpp.drogon.request.path",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->(?:path|getOriginalPath)\s*\(\s*\)`,
			ObjectType:  "drogon::HttpRequest",
			MethodName:  "path/getOriginalPath",
			Description: "Drogon HTTP request URL path",
			Assigns:     "return",
		},
		{
			ID:          "cpp.drogon.request.query",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->query\s*\(\s*\)`,
			ObjectType:  "drogon::HttpRequest",
			MethodName:  "query",
			Description: "Drogon HTTP request query string",
			Assigns:     "return",
		},
		{
			ID:          "cpp.drogon.request.json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->getJsonObject\s*\(\s*\)`,
			ObjectType:  "drogon::HttpRequest",
			MethodName:  "getJsonObject",
			Description: "Drogon HTTP request parsed JSON body",
			Assigns:     "return",
		},
		{
			ID:          "cpp.drogon.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->(?:bodyData|body)\s*\(\s*\)`,
			ObjectType:  "drogon::HttpRequest",
			MethodName:  "bodyData/body",
			Description: "Drogon HTTP request raw body data",
			Assigns:     "return",
		},

		// ── uWebSockets (uWS) sources ────────────────────────────────
		// uNetworking/uWebSockets is a widely deployed high-performance C++
		// HTTP/WebSocket server (the engine under uWebSockets.js). Request
		// handlers receive `uWS::HttpRequest *req`; the getUrl/getFullUrl/
		// getQuery/getMethod accessors return client-controlled
		// std::string_views. getHeader/getParameter are already covered by
		// the generic request-receiver heuristic, so only the genuinely
		// unregistered accessors are added here.
		{
			ID:          "cpp.uws.request.geturl",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->getUrl\s*\(`,
			ObjectType:  "uWS::HttpRequest",
			MethodName:  "getUrl",
			Description: "uWebSockets HttpRequest::getUrl() — client-controlled request path",
			Assigns:     "return",
		},
		{
			ID:          "cpp.uws.request.getfullurl",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->getFullUrl\s*\(`,
			ObjectType:  "uWS::HttpRequest",
			MethodName:  "getFullUrl",
			Description: "uWebSockets HttpRequest::getFullUrl() — client-controlled path plus query string",
			Assigns:     "return",
		},
		{
			ID:          "cpp.uws.request.getquery",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->getQuery\s*\(`,
			ObjectType:  "uWS::HttpRequest",
			MethodName:  "getQuery",
			Description: "uWebSockets HttpRequest::getQuery() — client-controlled query string / parameter",
			Assigns:     "return",
		},
		{
			ID:          "cpp.uws.request.getmethod",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `req->getMethod\s*\(`,
			ObjectType:  "uWS::HttpRequest",
			MethodName:  "getMethod",
			Description: "uWebSockets HttpRequest::getMethod() — client-controlled HTTP method string",
			Assigns:     "return",
		},

		// ── Oat++ (oatpp) sources ────────────────────────────────────
		{
			ID:          "cpp.oatpp.request.queryparam",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `->getQueryParameter\s*\(`,
			ObjectType:  "oatpp::web::protocol::http::incoming::Request",
			MethodName:  "getQueryParameter",
			Description: "Oat++ HTTP request query parameter",
			Assigns:     "return",
		},
		{
			ID:          "cpp.oatpp.request.header",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `->getHeader\s*\(`,
			ObjectType:  "oatpp::web::protocol::http::incoming::Request",
			MethodName:  "getHeader",
			Description: "Oat++ HTTP request header value",
			Assigns:     "return",
		},
		{
			ID:          "cpp.oatpp.request.body",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `->readBodyToString\s*\(`,
			ObjectType:  "oatpp::web::protocol::http::incoming::Request",
			MethodName:  "readBodyToString",
			Description: "Oat++ HTTP request body as string",
			Assigns:     "return",
		},

		// ── cpprestsdk (Casablanca) sources ──────────────────────────
		{
			ID:          "cpp.cpprest.request.extract_string",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:request|req)\.extract_string\s*\(`,
			ObjectType:  "web::http::http_request",
			MethodName:  "extract_string",
			Description: "cpprestsdk HTTP request body as string",
			Assigns:     "return",
		},
		{
			ID:          "cpp.cpprest.request.extract_json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:request|req)\.extract_json\s*\(`,
			ObjectType:  "web::http::http_request",
			MethodName:  "extract_json",
			Description: "cpprestsdk HTTP request body as JSON",
			Assigns:     "return",
		},
		{
			ID:          "cpp.cpprest.request.request_uri",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:request|req)\.request_uri\s*\(\s*\)`,
			ObjectType:  "web::http::http_request",
			MethodName:  "request_uri",
			Description: "cpprestsdk HTTP request URI",
			Assigns:     "return",
		},

		// --- hiredis Redis reply data (second-order injection) ---
		{
			ID:          "cpp.hiredis.command.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredisCommand\s*\(`,
			ObjectType:  "",
			MethodName:  "redisCommand",
			Description: "hiredis Redis command result (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.hiredis.commandargv.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredisCommandArgv\s*\(`,
			ObjectType:  "",
			MethodName:  "redisCommandArgv",
			Description: "hiredis Redis binary-safe command result (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},

		// --- redis-plus-plus (sw::redis::Redis) read commands ---
		// redis-plus-plus is a popular modern C++ Redis client (sw::redis
		// namespace, ~2.7k GitHub stars). Read methods return data stored
		// in Redis, which may be attacker-controlled if a previous write
		// path did not validate input — the canonical second-order taint
		// pattern. ObjectType "sw::redis::Redis" scopes matching to a
		// receiver named "redis" / "r" (matcher prefix-abbreviation).
		{
			ID:          "cpp.swredis.get",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.get\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "get",
			Description: "redis-plus-plus String GET (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.mget",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.mget\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "mget",
			Description: "redis-plus-plus multi-key MGET (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.hget",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.hget\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "hget",
			Description: "redis-plus-plus hash field GET (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.hgetall",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.hgetall\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "hgetall",
			Description: "redis-plus-plus all hash fields and values (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.hmget",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.hmget\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "hmget",
			Description: "redis-plus-plus multi-field hash GET (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.hkeys",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.hkeys\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "hkeys",
			Description: "redis-plus-plus hash field names (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.hvals",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.hvals\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "hvals",
			Description: "redis-plus-plus hash values (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.lrange",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.lrange\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "lrange",
			Description: "redis-plus-plus list range (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.lindex",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.lindex\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "lindex",
			Description: "redis-plus-plus list element by index (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.lpop",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.lpop\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "lpop",
			Description: "redis-plus-plus list left-pop (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.rpop",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.rpop\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "rpop",
			Description: "redis-plus-plus list right-pop (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.smembers",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.smembers\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "smembers",
			Description: "redis-plus-plus set members (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.spop",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.spop\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "spop",
			Description: "redis-plus-plus set pop (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.zrange",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.zrange\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "zrange",
			Description: "redis-plus-plus sorted-set range (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.swredis.zrangebyscore",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `\bredis\.zrangebyscore\s*\(`,
			ObjectType:  "sw::redis::Redis",
			MethodName:  "zrangebyscore",
			Description: "redis-plus-plus sorted-set range by score (data from potentially untrusted Redis store)",
			Assigns:     "return",
		},

		// ── MySQL Connector/C++ ResultSet column reads (second-order) ─
		// Oracle's MySQL Connector/C++ and MariaDB Connector/C++ expose
		// query results through the JDBC-style sql::ResultSet. getString /
		// getInt / getDouble / ... return column values that were stored
		// in the database — attacker-controlled if an earlier write path
		// did not validate the data (the canonical second-order taint
		// pattern). ObjectType "sql::ResultSet" scopes matching to a
		// receiver named "res" / "result" (matcher prefix-abbreviation
		// against "resultset"). Pairs with the cpp.mysql.connector.statement.*
		// SQL-injection sinks already in cpp_sinks.go.
		{
			ID:          "cpp.mysql.connector.resultset.getstring",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:res|result)\s*->\s*getString\s*\(`,
			ObjectType:  "sql::ResultSet",
			MethodName:  "getString",
			Description: "MySQL/MariaDB Connector/C++ ResultSet::getString column value (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mysql.connector.resultset.getint",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:res|result)\s*->\s*getInt\s*\(`,
			ObjectType:  "sql::ResultSet",
			MethodName:  "getInt",
			Description: "MySQL/MariaDB Connector/C++ ResultSet::getInt column value (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mysql.connector.resultset.getint64",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:res|result)\s*->\s*getInt64\s*\(`,
			ObjectType:  "sql::ResultSet",
			MethodName:  "getInt64",
			Description: "MySQL/MariaDB Connector/C++ ResultSet::getInt64 column value (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mysql.connector.resultset.getuint",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:res|result)\s*->\s*getUInt\s*\(`,
			ObjectType:  "sql::ResultSet",
			MethodName:  "getUInt",
			Description: "MySQL/MariaDB Connector/C++ ResultSet::getUInt column value (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mysql.connector.resultset.getuint64",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:res|result)\s*->\s*getUInt64\s*\(`,
			ObjectType:  "sql::ResultSet",
			MethodName:  "getUInt64",
			Description: "MySQL/MariaDB Connector/C++ ResultSet::getUInt64 column value (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mysql.connector.resultset.getdouble",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:res|result)\s*->\s*getDouble\s*\(`,
			ObjectType:  "sql::ResultSet",
			MethodName:  "getDouble",
			Description: "MySQL/MariaDB Connector/C++ ResultSet::getDouble column value (stored data may be tainted — second-order injection)",
			Assigns:     "return",
		},

		// ── mongocxx query-result document reads (second-order) ──────
		// mongocxx is the official MongoDB C++ driver. find_one and the
		// find_one_and_* atomic mutators return the matched BSON document,
		// whose fields hold data stored in MongoDB — attacker-controlled
		// if an earlier write path did not validate it. ObjectType
		// "mongocxx::collection" scopes matching to a receiver named
		// "coll" / "collection". These coexist with the cpp.mongocxx.*
		// NoSQL-injection sinks (which fire on a tainted *filter* argument);
		// here the *return value* is tainted instead.
		{
			ID:          "cpp.mongocxx.find_one.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:coll|collection)\s*\.\s*find_one\s*\(`,
			ObjectType:  "mongocxx::collection",
			MethodName:  "find_one",
			Description: "mongocxx collection.find_one result document (data read from MongoDB may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mongocxx.find_one_and_update.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:coll|collection)\s*\.\s*find_one_and_update\s*\(`,
			ObjectType:  "mongocxx::collection",
			MethodName:  "find_one_and_update",
			Description: "mongocxx collection.find_one_and_update result document (data read from MongoDB may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mongocxx.find_one_and_replace.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:coll|collection)\s*\.\s*find_one_and_replace\s*\(`,
			ObjectType:  "mongocxx::collection",
			MethodName:  "find_one_and_replace",
			Description: "mongocxx collection.find_one_and_replace result document (data read from MongoDB may be tainted — second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.mongocxx.find_one_and_delete.result",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:coll|collection)\s*\.\s*find_one_and_delete\s*\(`,
			ObjectType:  "mongocxx::collection",
			MethodName:  "find_one_and_delete",
			Description: "mongocxx collection.find_one_and_delete result document (data read from MongoDB may be tainted — second-order injection)",
			Assigns:     "return",
		},

		// ── AWS SDK for C++ read-result sources (second-order) ───────
		// The official AWS SDK for C++ exposes service clients whose read
		// operations return an Outcome wrapping data that was previously
		// stored in the service (S3 object bodies, DynamoDB items, SQS
		// message bodies, Kinesis records). If an earlier write path placed
		// attacker-controlled data there without validation, it re-enters the
		// program tainted on read — a classic second-order injection vector.
		// These pair with the existing cpp.aws.* injection SINKS in
		// cpp_sinks.go (Athena / DynamoDB PartiQL / Redshift Data SQL setters),
		// which fire on a tainted query string; here the *return value* of the
		// read is tainted. ObjectType is the fully-qualified client class so
		// the tsflow matcher scopes to a receiver named like the client
		// (e.g. `s3Client`, `dynamoDbClient`, `sqsClient`, `kinesisClient`),
		// matching the client type's final `::` segment.
		{
			ID:          "cpp.aws.s3.getobject",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `(?:s3[Cc]lient|s3|client)\s*\.\s*GetObject\s*\(`,
			ObjectType:  "Aws::S3::S3Client",
			MethodName:  "GetObject",
			Description: "AWS SDK for C++ S3Client::GetObject result — object body read from S3 (attacker may have uploaded the object; second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.aws.dynamodb.getitem",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:dynamo[Dd]b[Cc]lient|dynamo[Cc]lient|dynamodb|client)\s*\.\s*GetItem\s*\(`,
			ObjectType:  "Aws::DynamoDB::DynamoDBClient",
			MethodName:  "GetItem",
			Description: "AWS SDK for C++ DynamoDBClient::GetItem result — single item read from a table (attacker-controlled attribute values; second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.aws.dynamodb.query",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:dynamo[Dd]b[Cc]lient|dynamo[Cc]lient|dynamodb)\s*\.\s*Query\s*\(`,
			ObjectType:  "Aws::DynamoDB::DynamoDBClient",
			MethodName:  "Query",
			Description: "AWS SDK for C++ DynamoDBClient::Query result — items read from a table (attacker-controlled attribute values; second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.aws.dynamodb.scan",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:dynamo[Dd]b[Cc]lient|dynamo[Cc]lient|dynamodb)\s*\.\s*Scan\s*\(`,
			ObjectType:  "Aws::DynamoDB::DynamoDBClient",
			MethodName:  "Scan",
			Description: "AWS SDK for C++ DynamoDBClient::Scan result — items read from a table (attacker-controlled attribute values; second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.aws.dynamodb.batchgetitem",
			Category:    taint.SrcDatabase,
			Language:    rules.LangCPP,
			Pattern:     `(?:dynamo[Dd]b[Cc]lient|dynamo[Cc]lient|dynamodb|client)\s*\.\s*BatchGetItem\s*\(`,
			ObjectType:  "Aws::DynamoDB::DynamoDBClient",
			MethodName:  "BatchGetItem",
			Description: "AWS SDK for C++ DynamoDBClient::BatchGetItem result — items read from one or more tables (attacker-controlled attribute values; second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.aws.sqs.receivemessage",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `(?:sqs[Cc]lient|sqs|client)\s*\.\s*ReceiveMessage\s*\(`,
			ObjectType:  "Aws::SQS::SQSClient",
			MethodName:  "ReceiveMessage",
			Description: "AWS SDK for C++ SQSClient::ReceiveMessage result — message body read from an SQS queue (attacker-controlled producer; second-order injection)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.aws.kinesis.getrecords",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `(?:kinesis[Cc]lient|kinesis|client)\s*\.\s*GetRecords\s*\(`,
			ObjectType:  "Aws::Kinesis::KinesisClient",
			MethodName:  "GetRecords",
			Description: "AWS SDK for C++ KinesisClient::GetRecords result — records read from a Kinesis stream (attacker-controlled producer; second-order injection)",
			Assigns:     "return",
		},

		// ── External data sources (SrcExternal) ─────────────────────
		// Message queues, IPC, and pub/sub systems that receive
		// attacker-controlled data from external services.

		// Kafka (librdkafka C API — ~5k GitHub stars, used by Confluent)
		{
			ID:          "cpp.rdkafka.consumer_poll",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\brd_kafka_consumer_poll\s*\(`,
			ObjectType:  "",
			MethodName:  "rd_kafka_consumer_poll",
			Description: "librdkafka Kafka consumer poll (message payload from topic)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.rdkafka.consume",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\brd_kafka_consume\s*\(`,
			ObjectType:  "",
			MethodName:  "rd_kafka_consume",
			Description: "librdkafka legacy per-topic consumer (message from partition)",
			Assigns:     "return",
		},

		// RabbitMQ (rabbitmq-c — official C client)
		{
			ID:          "cpp.rabbitmqc.basic_get",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bamqp_basic_get\s*\(`,
			ObjectType:  "",
			MethodName:  "amqp_basic_get",
			Description: "rabbitmq-c synchronous get (message from RabbitMQ queue)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.rabbitmqc.consume_message",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bamqp_consume_message\s*\(`,
			ObjectType:  "",
			MethodName:  "amqp_consume_message",
			Description: "rabbitmq-c blocking consume (message from RabbitMQ queue)",
			Assigns:     "return",
		},

		// ZeroMQ (libzmq C API — 10k+ GitHub stars)
		{
			ID:          "cpp.zmq.recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bzmq_recv\s*\(`,
			ObjectType:  "",
			MethodName:  "zmq_recv",
			Description: "ZeroMQ receive (data from ZMQ socket peer)",
			Assigns:     "arg:1",
		},
		{
			ID:          "cpp.zmq.msg_recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bzmq_msg_recv\s*\(`,
			ObjectType:  "",
			MethodName:  "zmq_msg_recv",
			Description: "ZeroMQ message receive (message object from ZMQ socket)",
			Assigns:     "arg:0",
		},

		// MQTT (Eclipse Paho C — official Eclipse IoT client)
		{
			ID:          "cpp.mqtt.client_receive",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bMQTTClient_receive\s*\(`,
			ObjectType:  "",
			MethodName:  "MQTTClient_receive",
			Description: "Paho MQTT C client receive (message from MQTT broker)",
			Assigns:     "return",
		},

		// D-Bus (systemd sd-bus — Linux IPC)
		{
			ID:          "cpp.sdbus.message_read",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bsd_bus_message_read\s*\(`,
			ObjectType:  "",
			MethodName:  "sd_bus_message_read",
			Description: "systemd sd-bus message read (IPC data from D-Bus peer)",
			Assigns:     "return",
		},

		// nanomsg next-gen (nng — scalability protocol library)
		{
			ID:          "cpp.nng.recv",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bnng_recv\s*\(`,
			ObjectType:  "",
			MethodName:  "nng_recv",
			Description: "nng receive (data from nanomsg peer socket)",
			Assigns:     "arg:1",
		},

		// NATS (nats.c — official NATS C client)
		{
			ID:          "cpp.nats.subscription_nextmsg",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bnatsSubscription_NextMsg\s*\(`,
			ObjectType:  "",
			MethodName:  "natsSubscription_NextMsg",
			Description: "NATS subscription next message (message from NATS server)",
			Assigns:     "return",
		},

		// --- Archive entry sources (Zip Slip / Tar Slip, CWE-22) ---
		//
		// Paths read from archive headers are attacker-controlled: an archive
		// entry name like "../../etc/passwd" will traverse out of the extraction
		// directory when passed unchecked to fopen / ofstream / remove.
		// References: Snyk "Zip Slip" (2018, CVE-2018-1000877 libarchive),
		// CVE-2018-20482 (GNU tar hardlink), libzip path-traversal advisories.
		// Safe flows route the returned string through cpp.basename (or a
		// canonicalize + containment check) before the sink — bare
		// canonicalization (realpath / std::filesystem::canonical) is NOT a
		// sanitizer; see the note in cpp_sanitizers.go.

		// libarchive (github.com/libarchive/libarchive) — backs bsdtar,
		// pacman, and most BSD utilities; also widely used from C++.
		{
			ID:          "cpp.libarchive.entry.pathname",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\barchive_entry_pathname(?:_utf8|_w)?\s*\(`,
			ObjectType:  "",
			MethodName:  "archive_entry_pathname/archive_entry_pathname_utf8/archive_entry_pathname_w",
			Description: "libarchive archive_entry_pathname returns the attacker-controlled entry path from the archive header (Zip Slip / Tar Slip source, CWE-22)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.libarchive.entry.hardlink",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\barchive_entry_hardlink(?:_utf8|_w)?\s*\(`,
			ObjectType:  "",
			MethodName:  "archive_entry_hardlink/archive_entry_hardlink_utf8/archive_entry_hardlink_w",
			Description: "libarchive archive_entry_hardlink returns the attacker-controlled hardlink target from the archive header (CVE-2018-20482 GNU tar, CWE-22)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.libarchive.entry.symlink",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\barchive_entry_symlink(?:_utf8|_w)?\s*\(`,
			ObjectType:  "",
			MethodName:  "archive_entry_symlink/archive_entry_symlink_utf8/archive_entry_symlink_w",
			Description: "libarchive archive_entry_symlink returns the attacker-controlled symlink target from the archive header (Zip Slip variant, CWE-22)",
			Assigns:     "return",
		},

		// libzip (github.com/nih-at/libzip) — dominant zip library in C/C++.
		{
			ID:          "cpp.libzip.get_name",
			Category:    taint.SrcExternal,
			Language:    rules.LangCPP,
			Pattern:     `\bzip_get_name\s*\(`,
			ObjectType:  "",
			MethodName:  "zip_get_name",
			Description: "libzip zip_get_name returns the attacker-controlled entry name from a zip archive (Zip Slip source, CWE-22)",
			Assigns:     "return",
		},

		// ── Boost.Beast HTTP request additional input methods ─────────
		// The existing cpp.boost.beast.http.request.{body,target} entries
		// match in tsflow. The .header entry uses MethodName "header_field"
		// which only matches via the Layer 1 regex Pattern (tsflow ignores
		// Pattern), so the actual at()/find() field accessors are not
		// detected by the dataflow walker. The entries below add tsflow
		// matcher coverage for the remaining commonly-used header/method
		// accessors in boost::beast::http::message<isRequest, Body, Fields>.
		{
			ID:          "cpp.boost.beast.http.request.method_string",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:request|req)\.method_string\s*\(`,
			ObjectType:  "boost::beast::http::request",
			MethodName:  "method_string",
			Description: "Boost.Beast HTTP request method as string (client-controlled HTTP verb)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.boost.beast.http.request.at",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:request|req)\.at\s*\(\s*(?:boost::beast::)?http::field::`,
			ObjectType:  "boost::beast::http::request",
			MethodName:  "at",
			Description: "Boost.Beast HTTP request header value via at() — throws on missing field, returns string_view",
			Assigns:     "return",
		},
		{
			ID:          "cpp.boost.beast.http.request.find",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:request|req)\.find\s*\(\s*(?:boost::beast::)?http::field::`,
			ObjectType:  "boost::beast::http::request",
			MethodName:  "find",
			Description: "Boost.Beast HTTP request header iterator via find() — caller dereferences ->value() to obtain the user-controlled header value",
			Assigns:     "return",
		},

		// ── gRPC C++ ServerContext input sources ──────────────────────
		// gRPC's ServerContext exposes client-supplied HTTP/2 metadata
		// (headers) and a peer URI string. Per the gRPC C++ docs
		// (https://grpc.github.io/grpc/cpp/classgrpc_1_1_server_context.html),
		// peer() is "never authenticated or subject to security-related
		// code and must not be used for authentication functionality."
		// AuthContext property values are NOT modeled here because they
		// are derived from authenticated TLS material.
		{
			ID:          "cpp.grpc.servercontext.client_metadata",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:context|ctx)\s*->\s*client_metadata\s*\(\s*\)`,
			ObjectType:  "grpc::ServerContext",
			MethodName:  "client_metadata",
			Description: "gRPC ServerContext::client_metadata() returns client-supplied HTTP/2 headers as a multimap (CWE-20)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.grpc.servercontext.peer",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:context|ctx)\s*->\s*peer\s*\(\s*\)`,
			ObjectType:  "grpc::ServerContext",
			MethodName:  "peer",
			Description: "gRPC ServerContext::peer() returns a peer URI string that gRPC docs explicitly mark as unauthenticated (CWE-20)",
			Assigns:     "return",
		},

		// ── simdjson — JSON parse → deserialized source ───────────────
		// simdjson (github.com/simdjson/simdjson) is the dominant high-speed
		// JSON parser in C++. The On-Demand API (`parser.iterate(...)`) and the
		// DOM API (`parser.parse(...)`) both return a document view over data
		// that originated from an untrusted JSON byte buffer. Scoped to a
		// receiver literally named "parser"/"simdjson" (the canonical variable
		// names in the simdjson docs) so a bare `.iterate(`/`.parse(` on an
		// unrelated object does not substring-match.
		{
			ID:          "cpp.simdjson.iterate",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCPP,
			Pattern:     `(?:simdjson|parser)\w*\.iterate\s*\(`,
			ObjectType:  "simdjson::ondemand::parser",
			MethodName:  "iterate",
			Description: "simdjson On-Demand parser.iterate() yields a document over untrusted JSON bytes (deserialized source)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.simdjson.parse",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangCPP,
			Pattern:     `(?:simdjson|parser)\w*\.parse\s*\(`,
			ObjectType:  "simdjson::dom::parser",
			MethodName:  "parse",
			Description: "simdjson DOM parser.parse() yields an element tree over untrusted JSON bytes (deserialized source)",
			Assigns:     "return",
		},
		{
			ID:          "cpp.simdjson.padded_string.load",
			Category:    taint.SrcFileRead,
			Language:    rules.LangCPP,
			Pattern:     `simdjson::padded_string::load\s*\(`,
			ObjectType:  "simdjson::padded_string",
			MethodName:  "load",
			Description: "simdjson padded_string::load reads a JSON file from a (possibly user-controlled) path into a buffer (file-read source)",
			Assigns:     "return",
		},

		// ── Wt / Witty web toolkit request sources ────────────────────
		// Wt (github.com/emweb/wt) is a widget-centric C++ web framework.
		// WEnvironment exposes the client-supplied request data: query
		// parameters, cookies, and raw CGI/header values. Per the Wt docs,
		// getParameter/getCookie/getCgiValue/headerValue all return strings
		// taken directly from the HTTP request. Scoped to a receiver named
		// "env"/"environment" to avoid bare-method substring collisions.
		{
			ID:          "cpp.wt.environment.getparameter",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:env|environment)\s*(?:\.|->)\s*getParameter\s*\(`,
			ObjectType:  "Wt::WEnvironment",
			MethodName:  "getParameter",
			Description: "Wt WEnvironment::getParameter returns a client-supplied query/POST parameter value",
			Assigns:     "return",
		},
		{
			ID:          "cpp.wt.environment.getcookie",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:env|environment)\s*(?:\.|->)\s*getCookie\s*\(`,
			ObjectType:  "Wt::WEnvironment",
			MethodName:  "getCookie",
			Description: "Wt WEnvironment::getCookie returns a client-supplied cookie value",
			Assigns:     "return",
		},
		{
			ID:          "cpp.wt.environment.headervalue",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `(?:env|environment)\s*(?:\.|->)\s*(?:getCgiValue|headerValue)\s*\(`,
			ObjectType:  "Wt::WEnvironment",
			MethodName:  "getCgiValue/headerValue",
			Description: "Wt WEnvironment::getCgiValue/headerValue returns a raw client-supplied CGI variable or HTTP header value",
			Assigns:     "return",
		},

		// ── libmicrohttpd / GNU MHD request sources ───────────────────
		// libmicrohttpd (GNU MHD) is a small embeddable HTTP server library.
		// MHD_lookup_connection_value(_n) returns a single GET argument,
		// POST field, header, or cookie value selected by MHD_ValueKind;
		// the value comes straight from the client request. MHD_get_connection_values
		// iterates all values of a kind, passing each to a user callback.
		{
			ID:          "cpp.microhttpd.lookup_connection_value",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `\bMHD_lookup_connection_value(?:_n|5)?\s*\(`,
			ObjectType:  "",
			MethodName:  "MHD_lookup_connection_value/MHD_lookup_connection_value_n",
			Description: "libmicrohttpd MHD_lookup_connection_value returns a client-supplied GET/POST/header/cookie value",
			Assigns:     "return",
		},
		{
			ID:          "cpp.microhttpd.get_connection_values",
			Category:    taint.SrcUserInput,
			Language:    rules.LangCPP,
			Pattern:     `\bMHD_get_connection_values\s*\(`,
			ObjectType:  "",
			MethodName:  "MHD_get_connection_values",
			Description: "libmicrohttpd MHD_get_connection_values iterates all client-supplied request values of a kind into a callback",
			Assigns:     "return",
		},

		// ── CppCMS (cppcms::http::request) ───────────────────────────
		// CppCMS handlers call the inherited request() accessor and read
		// attacker-controlled values off it. Receiver-scoped to
		// "cppcms::http::request" so a generic .get()/.post() on another object
		// is not seeded.
		{ID: "cpp.cppcms.request.get", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.get\s*\(`, ObjectType: "cppcms::http::request", MethodName: "get", Description: "CppCMS request().get() — GET/POST query value (attacker-controlled)", Assigns: "return"},
		{ID: "cpp.cppcms.request.post", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.post\s*\(`, ObjectType: "cppcms::http::request", MethodName: "post", Description: "CppCMS request().post() — POST form value (attacker-controlled)", Assigns: "return"},
		{ID: "cpp.cppcms.request.cookie_by_name", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.cookie_by_name\s*\(`, ObjectType: "cppcms::http::request", MethodName: "cookie_by_name", Description: "CppCMS request().cookie_by_name() — request cookie value (attacker-controlled)", Assigns: "return"},
		{ID: "cpp.cppcms.request.getenv", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.getenv\s*\(`, ObjectType: "cppcms::http::request", MethodName: "getenv", Description: "CppCMS request().getenv() — CGI environment value (HTTP_* headers, attacker-controlled)", Assigns: "return"},
		{ID: "cpp.cppcms.request.raw_post_data", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.raw_post_data\s*\(`, ObjectType: "cppcms::http::request", MethodName: "raw_post_data", Description: "CppCMS request().raw_post_data() — raw request body (attacker-controlled)", Assigns: "return"},
		{ID: "cpp.cppcms.request.query_string", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.query_string\s*\(`, ObjectType: "cppcms::http::request", MethodName: "query_string", Description: "CppCMS request().query_string() — raw query string (attacker-controlled)", Assigns: "return"},
		{ID: "cpp.cppcms.request.path_info", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\.path_info\s*\(`, ObjectType: "cppcms::http::request", MethodName: "path_info", Description: "CppCMS request().path_info() — request path (attacker-controlled)", Assigns: "return"},

		// ── Generic HTTP request query accessor ──────────────────────
		// Many C++ web frameworks (Crow, custom request wrappers) expose a
		// `req.query("name")` / `request.query("name")` accessor returning
		// a client-controlled query-string value. The empty-paren Pistache
		// form (`request.query()`) is covered above; this catches the
		// argument-taking lookup form used by Crow-style handlers.
		{ID: "cpp.request.query.named", Category: taint.SrcUserInput, Language: rules.LangCPP, Pattern: `\b(?:req|request)\.query\s*\(\s*["']`, ObjectType: "HttpRequest", MethodName: "query", Description: "HTTP request query parameter accessor (attacker-controlled)", Assigns: "return"},
	}
}
