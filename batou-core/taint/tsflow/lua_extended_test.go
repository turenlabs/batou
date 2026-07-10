package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Lua FileRead sinks (CWE-22)
// =========================================================================

func TestLua_LfsDirPathTraversal(t *testing.T) {
	code := `
local lfs = require("lfs")
function list_dir()
    local args = ngx.req.get_uri_args()
    local path = args["dir"]
    for entry in lfs.dir(path) do
        ngx.say(entry)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for ngx.req.get_uri_args -> lfs.dir")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_LfsSymlinkattributesPathTraversal(t *testing.T) {
	code := `
local lfs = require("lfs")
function check_link()
    local args = ngx.req.get_uri_args()
    local path = args["path"]
    local attr = lfs.symlinkattributes(path)
    return attr
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for ngx.req.get_uri_args -> lfs.symlinkattributes")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua Command injection via ngx.pipe (CWE-78)
// =========================================================================

func TestLua_NgxPipeSpawnCommandInjection(t *testing.T) {
	code := `
function run_command()
    local cmd = io.read()
    local proc = ngx.pipe.spawn(cmd)
    local data = proc:stdout_read_line()
    ngx.say(data)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for io.read -> ngx.pipe.spawn")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua Header injection via ngx.req.set_header (CWE-113)
// =========================================================================

func TestLua_NgxReqSetHeaderInjection(t *testing.T) {
	code := `
function set_custom_header()
    local args = ngx.req.get_uri_args()
    local val = args["header_val"]
    ngx.req.set_header("X-Custom", val)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header injection flow for ngx.req.get_uri_args -> ngx.req.set_header")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua Log injection (CWE-117)
// =========================================================================

func TestLua_IoWriteLogInjection(t *testing.T) {
	code := `
function log_request()
    local user = io.read()
    io.write("User logged in: " .. user)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for io.read -> io.write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_IoStderrWriteLogInjection(t *testing.T) {
	code := `
function log_error()
    local input = io.read()
    io.stderr:write("Error: " .. input)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for io.read -> io.stderr:write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua sanitizer tests
// =========================================================================

func TestLua_CjsonEncodeSanitizesXSS(t *testing.T) {
	code := `
local cjson = require("cjson")
function json_response()
    local data = io.read()
    local safe = cjson.encode(data)
    ngx.say(safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Error("cjson.encode should sanitize XSS flow, but high-confidence HTMLOutput flow found")
		}
	}
}

func TestLua_NgxReGsubSanitizesHeader(t *testing.T) {
	code := `
function safe_header()
    local args = ngx.req.get_uri_args()
    local val = args["val"]
    local clean = ngx.re.gsub(val, "[\r\n]", "", "jo")
    ngx.req.set_header("X-Custom", clean)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader && f.Confidence > 0.5 {
			t.Error("ngx.re.gsub should sanitize header injection flow, but high-confidence Header flow found")
		}
	}
}

// =========================================================================
// Lua FileRead — io.lines with tainted path (CWE-22)
// =========================================================================

func TestLua_IoLinesFilePathTraversal(t *testing.T) {
	code := `
function read_lines()
    local args = ngx.req.get_uri_args()
    local path = args["file"]
    for line in io.lines(path) do
        ngx.say(line)
    end
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected FileRead flow for ngx.req.get_uri_args -> io.lines")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua path traversal sanitizer tests (CWE-22 prevention)
// =========================================================================

func TestLua_PosixRealpathSanitizesFileRead(t *testing.T) {
	code := `
local posix = require("posix")
function safe_read()
    local args = ngx.req.get_uri_args()
    local path = args["file"]
    local resolved = posix.realpath(path)
    local f = io.open(resolved)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("posix.realpath should sanitize FileRead flow, but high-confidence flow found")
		}
	}
}

func TestLua_PlPathNormpathSanitizesFileRead(t *testing.T) {
	code := `
local pl_path = require("pl.path")
function safe_read()
    local args = ngx.req.get_uri_args()
    local path = args["file"]
    local clean = pl.path.normpath(path)
    local f = io.open(clean)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("pl.path.normpath should sanitize FileRead flow, but high-confidence flow found")
		}
	}
}

func TestLua_PlPathBasenameSanitizesFileRead(t *testing.T) {
	code := `
local pl_path = require("pl.path")
function safe_read()
    local args = ngx.req.get_uri_args()
    local filename = args["file"]
    local base = pl.path.basename(filename)
    local f = io.open("/uploads/" .. base)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("pl.path.basename should sanitize FileRead flow, but high-confidence flow found")
		}
	}
}

func TestLua_StringFindDotDotGuardSanitizesFileRead(t *testing.T) {
	code := `
function safe_read()
    local args = ngx.req.get_uri_args()
    local path = args["file"]
    if string.find(path, "..") then
        ngx.exit(403)
        return
    end
    local f = io.open(path)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("string.find(..) guard should sanitize FileRead flow, but high-confidence flow found")
		}
	}
}

// =========================================================================
// Lua Command injection — vulnerable patterns (CWE-78)
// =========================================================================

func TestLua_OsExecuteCommandInjection(t *testing.T) {
	code := `
function handler()
    local cmd = io.read()
    os.execute(cmd)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for io.read -> os.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestLua_IoPopenCommandInjection(t *testing.T) {
	code := `
function handler()
    local args = ngx.req.get_uri_args()
    local cmd = args["cmd"]
    local handle = io.popen(cmd)
    local result = handle:read("*a")
    ngx.say(result)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for ngx.req.get_uri_args -> io.popen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Lua Command injection — sanitizer tests (CWE-78 prevention)
// =========================================================================

func TestLua_PlUtilsQuoteArgSanitizesCommand(t *testing.T) {
	code := `
local utils = require("pl.utils")
function handler()
    local input = io.read()
    local safe = pl.utils.quote_arg(input)
    os.execute("echo " .. safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Error("pl.utils.quote_arg should sanitize command injection, but high-confidence flow found")
		}
	}
}

func TestLua_ShellEscapeSanitizesCommand(t *testing.T) {
	code := `
function handler()
    local input = io.read()
    local safe = shell_escape(input)
    os.execute("echo " .. safe)
end
`
	flows := Analyze(code, "/app/handler.lua", rules.LangLua)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Error("shell_escape should sanitize command injection, but high-confidence flow found")
		}
	}
}

