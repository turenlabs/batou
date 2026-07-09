package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Kotlin Redis Lua script + raw command injection sinks (CWE-94, CWE-77).
// Covers Jedis, Lettuce (RedisCommands), and Spring Data Redis DefaultRedisScript.

// ---------- Jedis.eval (CWE-94) ----------

func TestKotlin_Jedis_Eval_LuaInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis

fun runScript(input: String) {
    val jedis = Jedis("localhost")
    val script = "return redis.call('GET', '" + input + "')"
    jedis.eval(script)
}
`
	flows := Analyze(code, "/app/RedisDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.jedis.eval" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Lua injection finding for Jedis.eval; got flows: %+v", flows)
	}
}

// ---------- Jedis.evalsha (CWE-94) ----------

func TestKotlin_Jedis_EvalSha_DigestInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis

fun runStored(input: String) {
    val jedis = Jedis("localhost")
    val sha = input
    jedis.evalsha(sha)
}
`
	flows := Analyze(code, "/app/RedisDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.jedis.evalsha" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected eval finding for Jedis.evalsha; got flows: %+v", flows)
	}
}

// ---------- Jedis.scriptLoad (CWE-94) ----------

func TestKotlin_Jedis_ScriptLoad_PersistRCE(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis

fun loadScript(input: String) {
    val jedis = Jedis("localhost")
    val body = "return " + input
    jedis.scriptLoad(body)
}
`
	flows := Analyze(code, "/app/RedisDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.jedis.scriptload" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected eval finding for Jedis.scriptLoad; got flows: %+v", flows)
	}
}

// ---------- Jedis.sendCommand (CWE-77) ----------

func TestKotlin_Jedis_SendCommand_RawInjection(t *testing.T) {
	code := `
import redis.clients.jedis.Jedis
import redis.clients.jedis.Protocol

fun runCmd(input: String) {
    val jedis = Jedis("localhost")
    jedis.sendCommand(Protocol.Command.SET, "key", input)
}
`
	flows := Analyze(code, "/app/RedisDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Sink.ID == "kotlin.jedis.sendcommand" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected command injection finding for Jedis.sendCommand; got flows: %+v", flows)
	}
}

// ---------- Lettuce RedisCommands.eval (CWE-94) ----------

func TestKotlin_Lettuce_Eval_LuaInjection(t *testing.T) {
	code := `
import io.lettuce.core.RedisClient
import io.lettuce.core.api.sync.RedisCommands

fun runScript(input: String) {
    val client = RedisClient.create("redis://localhost")
    val redis: RedisCommands<String, String> = client.connect().sync()
    val script = "return redis.call('GET', '" + input + "')"
    redis.eval(script, io.lettuce.core.ScriptOutputType.VALUE)
}
`
	flows := Analyze(code, "/app/LettuceDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.lettuce.eval" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected Lua injection finding for Lettuce eval; got flows: %+v", flows)
	}
}

// ---------- Lettuce RedisCommands.evalsha (CWE-94) ----------

func TestKotlin_Lettuce_EvalSha_DigestInjection(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands

fun runStored(input: String, redis: RedisCommands<String, String>) {
    val sha = input
    redis.evalsha(sha, io.lettuce.core.ScriptOutputType.VALUE)
}
`
	flows := Analyze(code, "/app/LettuceDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.lettuce.evalsha" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected eval finding for Lettuce evalsha; got flows: %+v", flows)
	}
}

// ---------- Lettuce RedisCommands.scriptLoad (CWE-94) ----------

func TestKotlin_Lettuce_ScriptLoad_PersistRCE(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands

fun loadScript(input: String, redis: RedisCommands<String, String>) {
    val body = "return " + input
    redis.scriptLoad(body)
}
`
	flows := Analyze(code, "/app/LettuceDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.lettuce.scriptload" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected eval finding for Lettuce scriptLoad; got flows: %+v", flows)
	}
}

// ---------- Lettuce RedisCommands.dispatch (CWE-77) ----------

func TestKotlin_Lettuce_Dispatch_RawInjection(t *testing.T) {
	code := `
import io.lettuce.core.api.sync.RedisCommands
import io.lettuce.core.protocol.CommandArgs
import io.lettuce.core.codec.StringCodec

fun runCmd(input: String, redis: RedisCommands<String, String>) {
    val args = CommandArgs(StringCodec.UTF8).addKey("user").addValue(input)
    redis.dispatch(io.lettuce.core.protocol.CommandType.SET, output, args)
}
`
	flows := Analyze(code, "/app/LettuceDao.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Sink.ID == "kotlin.lettuce.dispatch" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected command injection finding for Lettuce dispatch; got flows: %+v", flows)
	}
}

// ---------- Spring Data Redis DefaultRedisScript constructor (CWE-94) ----------

func TestKotlin_Spring_DefaultRedisScript_New_LuaInjection(t *testing.T) {
	code := `
import org.springframework.data.redis.core.script.DefaultRedisScript

fun makeScript(input: String) {
    val body = "return " + input
    val script = DefaultRedisScript<Long>(body, Long::class.java)
}
`
	flows := Analyze(code, "/app/RedisScriptFactory.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.spring.defaultredisscript.new" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected eval finding for DefaultRedisScript constructor; got flows: %+v", flows)
	}
}

// ---------- Spring Data Redis DefaultRedisScript.setScriptText (CWE-94) ----------

func TestKotlin_Spring_DefaultRedisScript_SetScriptText_LuaInjection(t *testing.T) {
	code := `
import org.springframework.data.redis.core.script.DefaultRedisScript

fun mutateScript(input: String, script: DefaultRedisScript<Long>) {
    val body = "return " + input
    script.setScriptText(body)
}
`
	flows := Analyze(code, "/app/RedisScriptFactory.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval && f.Sink.ID == "kotlin.spring.defaultredisscript.setscripttext" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected eval finding for DefaultRedisScript.setScriptText; got flows: %+v", flows)
	}
}

// ---------- Negative: unrelated .eval() (e.g. JS Nashorn) must not match Jedis ----------

func TestKotlin_Redis_Negative_NonRedisEvalNoFP(t *testing.T) {
	code := `
import javax.script.ScriptEngineManager

fun js(input: String) {
    val engine = ScriptEngineManager().getEngineByName("nashorn")
    engine.eval(input)
}
`
	flows := Analyze(code, "/app/Js.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.ID == "kotlin.jedis.eval" || f.Sink.ID == "kotlin.lettuce.eval" {
			t.Errorf("Unexpected Redis eval finding on Nashorn engine.eval; got: %+v", f)
		}
	}
}
