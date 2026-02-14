package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
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
	}
}
