package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# StackExchange.Redis Lua script injection (CWE-94)
// ScriptEvaluate / ScriptEvaluateAsync / ScriptEvaluateReadOnly on IDatabase
// and ScriptLoad on IServer send the first argument to Redis as an EVAL or
// SCRIPT LOAD command — a tainted script body is arbitrary code execution on
// the Redis server.
// ===========================================================================

func TestCSharp_Sink_Redis_ScriptEvaluate(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

public class CacheController : Controller {
    private readonly IDatabase db;
    public IActionResult Run() {
        string userScript = Request.QueryString.Value;
        var result = db.ScriptEvaluate(userScript);
        return Ok(result.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.QueryString -> db.ScriptEvaluate (Redis Lua injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_Redis_ScriptEvaluateAsync(t *testing.T) {
	code := `
using System;
using System.Threading.Tasks;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

public class CacheController : Controller {
    private readonly IDatabase db;
    public async Task<IActionResult> Run() {
        string userScript = Request.Body.ToString();
        var result = await db.ScriptEvaluateAsync(userScript);
        return Ok(result.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.Body -> db.ScriptEvaluateAsync (Redis Lua injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_Redis_ScriptEvaluateReadOnly(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

public class CacheController : Controller {
    private readonly IDatabase db;
    public IActionResult Run() {
        string header = Request.Path.ToString();
        var result = db.ScriptEvaluateReadOnly(header);
        return Ok(result.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.Path -> db.ScriptEvaluateReadOnly (Redis Lua injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCSharp_Sink_Redis_ScriptLoad(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

public class CacheController : Controller {
    private readonly IServer server;
    public IActionResult Run() {
        string userScript = Request.QueryString.Value;
        byte[] sha = server.ScriptLoad(userScript);
        return Ok(Convert.ToBase64String(sha));
    }
}
`
	flows := Analyze(code, "/app/CacheController.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Request.QueryString -> server.ScriptLoad (tainted Lua script cached for EVALSHA)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Second-order: cached Redis data used as the body of a Lua script evaluation.
// Triggers on existing csharp.redis.stringget source -> new csharp.redis.scriptevaluate sink.
func TestCSharp_Sink_Redis_ScriptEvaluate_FromCachedData(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        string cached = db.StringGet("scripts:dynamic");
        db.ScriptEvaluate(cached);
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for Redis.StringGet -> Redis.ScriptEvaluate (second-order Lua injection)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Safe: the script body is a literal — only keys/values come from untrusted data.
// No eval-injection flow should be reported.
func TestCSharp_Sink_Redis_ScriptEvaluate_Safe_LiteralScript(t *testing.T) {
	code := `
using System;
using StackExchange.Redis;
using Microsoft.AspNetCore.Mvc;

public class CacheController : Controller {
    private readonly IDatabase db;
    public IActionResult Run() {
        string userKey = Request.QueryString.Value;
        var result = db.ScriptEvaluate("return redis.call('GET', KEYS[1])", new RedisKey[] { userKey });
        return Ok(result.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheController.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("did not expect SnkEval flow when the script body is a literal (only KEYS are tainted); got flow: %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}
