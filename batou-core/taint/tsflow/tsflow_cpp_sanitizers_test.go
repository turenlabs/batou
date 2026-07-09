package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C++ path traversal sanitizer tests (CWE-22)
// =========================================================================

func TestCPP_Filesystem_Filename_Sanitized(t *testing.T) {
	code := `
#include <filesystem>
#include <fstream>
#include <cstdlib>

void saveUpload() {
    char *userPath = getenv("UPLOAD_PATH");
    std::filesystem::path p(userPath);
    auto safe = p.filename();
    std::ofstream out("/uploads/" + safe.string());
    out << "data";
}
`
	flows := Analyze(code, "/app/upload_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Error("expected NO file write flow when path is sanitized via .filename()")
		}
	}
}

// path::lexically_normal() alone is NOT a sanitizer: it only collapses
// redundant segments lexically — lexically_normal("../../etc/passwd") is
// still "../../etc/passwd"; it does not reject escapes. The taint flow must
// survive. (This test previously asserted the opposite, which was unsound —
// see the filepath.Clean note in go_sanitizers.go and the os.path.normpath
// note in python_sanitizers.go; only canonicalize + containment is a
// defence. The old fixture also sank into std::ifstream's constructor,
// which the C++ config does not model as a sink — making the no-flow
// assertion vacuous — so the sink is now fopen.)
func TestCPP_Filesystem_LexicallyNormal_NotASanitizer(t *testing.T) {
	code := `
#include <filesystem>
#include <cstdio>
#include <cstdlib>

void readConfig() {
    std::string userPath = getenv("CONFIG_PATH");
    std::filesystem::path p = userPath;
    auto safe = p.lexically_normal();
    FILE *f = fopen(safe.c_str(), "r");
}
`
	flows := Analyze(code, "/app/config_safe.cpp", rules.LangCPP)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			found = true
		}
	}
	if !found {
		t.Error("lexically_normal() alone must NOT neutralize file taint — expected the traversal flow to still fire")
	}
}

// boost::filesystem::canonical() alone is NOT a sanitizer: it resolves
// "../../etc/passwd" to "/etc/passwd" — a real path OUTSIDE the safe base.
// The taint flow must survive. (Previously asserted the opposite — unsound;
// see TestCPP_Filesystem_LexicallyNormal_NotASanitizer. The sink is fopen
// because std::ifstream's constructor is not a modelled sink.)
func TestCPP_BoostFilesystem_Canonical_NotASanitizer(t *testing.T) {
	code := `
#include <boost/filesystem.hpp>
#include <cstdio>
#include <cstdlib>

void readFile() {
    char *userPath = getenv("FILE_PATH");
    auto safe = boost::filesystem::canonical(userPath);
    FILE *f = fopen(safe.c_str(), "r");
}
`
	flows := Analyze(code, "/app/boost_safe.cpp", rules.LangCPP)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead || f.Sink.Category == taint.SnkFileWrite {
			found = true
		}
	}
	if !found {
		t.Error("boost::filesystem::canonical() alone must NOT neutralize file taint — expected the traversal flow to still fire")
	}
}

// Negative test: path traversal WITHOUT sanitizer should produce a flow
func TestCPP_FileWrite_Unsanitized(t *testing.T) {
	code := `
#include <cstdio>
#include <cstdlib>

void saveFile() {
    char *userPath = getenv("FILE_PATH");
    FILE *f = fopen(userPath, "w");
    fputs("data", f);
}
`
	flows := Analyze(code, "/app/file_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for getenv -> fopen without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ eval / ReDoS sanitizer tests (CWE-94, CWE-1333)
// =========================================================================

func TestCPP_PCRE2_MatchLimit_Sanitized(t *testing.T) {
	code := `
#include <pcre2.h>
#include <cstdlib>

void search() {
    char *pattern = getenv("REGEX_PATTERN");
    pcre2_match_context *mctx = pcre2_match_context_create(NULL);
    pcre2_set_match_limit(mctx, 10000);
    int errcode;
    PCRE2_SIZE erroffset;
    pcre2_code *re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0, &errcode, &erroffset, NULL);
}
`
	flows := Analyze(code, "/app/pcre2_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow when PCRE2 match limit is set")
		}
	}
}

func TestCPP_Hyperscan_Compile_Sanitized(t *testing.T) {
	code := `
#include <hs/hs.h>
#include <cstdlib>

void search() {
    char *pattern = getenv("REGEX_PATTERN");
    hs_database_t *db;
    hs_compile_error_t *err;
    hs_compile(pattern, HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &db, &err);
}
`
	flows := Analyze(code, "/app/hs_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow when using Hyperscan (automata-based, no backtracking)")
		}
	}
}

func TestCPP_Lua_CheckType_Sanitized(t *testing.T) {
	code := `
#include <lua.h>
#include <lauxlib.h>
#include <cstdlib>

void execute() {
    char *input = getenv("USER_INPUT");
    lua_State *L = luaL_newstate();
    lua_pushstring(L, input);
    auto safe = luaL_checkinteger(L, -1);
    luaL_dostring(L, "print(safe)");
    lua_close(L);
}
`
	flows := Analyze(code, "/app/lua_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow when luaL_checkinteger enforces type")
		}
	}
}

func TestCPP_Duktape_RequireType_Sanitized(t *testing.T) {
	code := `
#include <duktape.h>
#include <cstdlib>

void execute() {
    char *input = getenv("USER_INPUT");
    duk_context *ctx = duk_create_heap_default();
    duk_push_string(ctx, input);
    auto safe = duk_require_int(ctx, -1);
}
`
	flows := Analyze(code, "/app/duktape_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval flow when duk_require_int enforces type")
		}
	}
}

// Negative test: eval WITHOUT sanitizer should produce a flow
func TestCPP_Lua_DoString_Unsanitized(t *testing.T) {
	code := `
#include <lua.h>
#include <lauxlib.h>
#include <cstdlib>

void execute() {
    char *userCode = getenv("LUA_CODE");
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    luaL_dostring(L, userCode);
    lua_close(L);
}
`
	flows := Analyze(code, "/app/lua_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for getenv -> luaL_dostring without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C++ deserialization sanitizer tests (CWE-502)
// =========================================================================

func TestCPP_CapnProto_ReaderOptions_Sanitized(t *testing.T) {
	code := `
#include <capnp/message.h>
#include <capnp/serialize.h>
#include <cstdlib>

void process() {
    char *input = getenv("CAPNP_INPUT");
    capnp::ReaderOptions opts;
    opts.traversalLimitInWords = 1024 * 1024;
    opts.nestingLimit = 32;
    auto words = kj::arrayPtr(reinterpret_cast<const capnp::word*>(input), strlen(input) / sizeof(capnp::word));
    capnp::FlatArrayMessageReader reader(words, opts);
}
`
	flows := Analyze(code, "/app/capnp_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("expected NO deser flow when capnp::ReaderOptions limits are set")
		}
	}
}

func TestCPP_Nlohmann_Accept_Sanitized(t *testing.T) {
	code := `
#include <nlohmann/json.hpp>
#include <cstdlib>

using json = nlohmann::json;

void process() {
    char *input = getenv("JSON_INPUT");
    if (json::accept(input)) {
        auto j = json::parse(input);
    }
}
`
	flows := Analyze(code, "/app/json_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("expected NO deser flow when json::accept() validates input first")
		}
	}
}

func TestCPP_Thrift_SizeLimit_Sanitized(t *testing.T) {
	code := `
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TBufferTransports.h>
#include <cstdlib>

void process() {
    char *input = getenv("THRIFT_INPUT");
    auto transport = std::make_shared<apache::thrift::transport::TMemoryBuffer>(
        (uint8_t*)input, strlen(input));
    auto protocol = std::make_shared<apache::thrift::protocol::TBinaryProtocol>(transport);
    protocol->setStringSizeLimit(1024 * 1024);
    protocol->setContainerSizeLimit(10000);
}
`
	flows := Analyze(code, "/app/thrift_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize {
			t.Error("expected NO deser flow when Thrift string/container size limits are set")
		}
	}
}

// Negative test: deserialization WITHOUT sanitizer should produce a flow
func TestCPP_Msgpack_Unpack_Unsanitized(t *testing.T) {
	code := `
#include <msgpack.hpp>
#include <cstdlib>

void process() {
    char *input = getenv("MSGPACK_INPUT");
    size_t len = strlen(input);
    msgpack::unpacked result;
    msgpack::unpack(result, input, len);
}
`
	flows := Analyze(code, "/app/msgpack_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deser flow for getenv -> msgpack::unpack without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
