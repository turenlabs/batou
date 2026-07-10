package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ===========================================================================
// C# StackExchange.Redis additional read sources for second-order taint.
//
// Reads previously-stored data from Redis. The returned bytes/strings carry
// taint from whatever earlier write put them there. Wired here through the
// existing csharp.redis.scriptevaluate sink (Redis EVAL) to demonstrate
// end-to-end second-order Lua injection — the same pattern the TestCSharp_
// Sink_Redis_ScriptEvaluate_FromCachedData test already proves for
// StringGet -> ScriptEvaluate.
// ===========================================================================

func TestCSharp_Source_Redis_HashKeys_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var fields = db.HashKeys("scripts:dynamic");
        db.ScriptEvaluate(fields.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashKeys -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_HashKeysAsync_ToScriptEvaluate(t *testing.T) {
	code := `
using System.Threading.Tasks;
using StackExchange.Redis;

public class CacheHandler {
    public async Task Handle(IDatabase db) {
        var fields = await db.HashKeysAsync("scripts:dynamic");
        await db.ScriptEvaluateAsync(fields.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashKeysAsync -> db.ScriptEvaluateAsync")
	}
}

func TestCSharp_Source_Redis_HashValues_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var values = db.HashValues("scripts:dynamic");
        db.ScriptEvaluate(values.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashValues -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_HashGetAll_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var entries = db.HashGetAll("scripts:dynamic");
        db.ScriptEvaluate(entries.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashGetAll -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_HashScan_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var entries = db.HashScan("scripts:dynamic");
        db.ScriptEvaluate(entries.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashScan -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_HashRandomField_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var field = db.HashRandomField("scripts:dynamic");
        db.ScriptEvaluate(field.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashRandomField -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_HashRandomFieldsWithValues_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var entries = db.HashRandomFieldsWithValues("scripts:dynamic", 5);
        db.ScriptEvaluate(entries.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.HashRandomFieldsWithValues -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_ListGetByIndex_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var item = db.ListGetByIndex("scripts:dynamic", 0);
        db.ScriptEvaluate(item.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.ListGetByIndex -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_ListLeftPop_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var item = db.ListLeftPop("scripts:queue");
        db.ScriptEvaluate(item.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.ListLeftPop -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_ListRightPop_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var item = db.ListRightPop("scripts:queue");
        db.ScriptEvaluate(item.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.ListRightPop -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_SetRandomMember_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var member = db.SetRandomMember("scripts:set");
        db.ScriptEvaluate(member.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.SetRandomMember -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_SetPop_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var member = db.SetPop("scripts:set");
        db.ScriptEvaluate(member.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.SetPop -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_SortedSetRangeByRank_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var entries = db.SortedSetRangeByRank("scripts:zset", 0, -1);
        db.ScriptEvaluate(entries.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.SortedSetRangeByRank -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_SortedSetRangeByValue_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var entries = db.SortedSetRangeByValue("scripts:zset");
        db.ScriptEvaluate(entries.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.SortedSetRangeByValue -> db.ScriptEvaluate")
	}
}

func TestCSharp_Source_Redis_StringGetRange_ToScriptEvaluate(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        var fragment = db.StringGetRange("scripts:dynamic", 0, 100);
        db.ScriptEvaluate(fragment.ToString());
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow for db.StringGetRange -> db.ScriptEvaluate")
	}
}

// Negative regression: hard-coded literal scripts must NOT trigger a flow even
// though ScriptEvaluate is a sink. Guards against catastrophic over-broadness
// from ObjectType "IDatabase" matching unrelated code.
func TestCSharp_Source_Redis_NegativeConstantScriptNoFlow(t *testing.T) {
	code := `
using StackExchange.Redis;

public class CacheHandler {
    public void Handle(IDatabase db) {
        db.ScriptEvaluate("return 1");
    }
}
`
	flows := Analyze(code, "/app/CacheHandler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("did not expect SnkEval flow for constant Lua script")
	}
}
