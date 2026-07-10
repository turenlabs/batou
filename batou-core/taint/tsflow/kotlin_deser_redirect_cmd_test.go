package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------- Jackson ObjectMapper.readValue (CWE-502) ----------

func TestKotlin_JacksonReadValue(t *testing.T) {
	code := `
import com.fasterxml.jackson.databind.ObjectMapper

fun handleRequest(input: String) {
    val objectMapper = ObjectMapper()
    val user = objectMapper.readValue(input, User::class.java)
    println(user.name)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.jackson.readvalue" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for Jackson ObjectMapper.readValue")
	}
}

// ---------- Jackson ObjectMapper.convertValue (CWE-502) ----------

func TestKotlin_JacksonConvertValue(t *testing.T) {
	code := `
import com.fasterxml.jackson.databind.ObjectMapper

fun convert(input: Any) {
    val objectMapper = ObjectMapper()
    val user = objectMapper.convertValue(input, User::class.java)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.jackson.convertvalue" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for Jackson ObjectMapper.convertValue")
	}
}

// ---------- SnakeYAML Yaml.load (CWE-502) ----------

func TestKotlin_SnakeYamlLoad(t *testing.T) {
	code := `
import org.yaml.snakeyaml.Yaml

fun parseConfig(input: String) {
    val yaml = Yaml()
    val config = yaml.load(input)
    println(config)
}
`
	flows := Analyze(code, "/app/ConfigParser.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.snakeyaml.load" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for SnakeYAML yaml.load()")
	}
}

func TestKotlin_SnakeYamlLoadAll(t *testing.T) {
	code := `
import org.yaml.snakeyaml.Yaml

fun parseAllConfigs(input: String) {
    val yaml = Yaml()
    val configs = yaml.loadAll(input)
}
`
	flows := Analyze(code, "/app/ConfigParser.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.snakeyaml.loadall" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for SnakeYAML yaml.loadAll()")
	}
}

// ---------- XMLDecoder (CWE-502) ----------

func TestKotlin_XMLDecoderReadObject(t *testing.T) {
	code := `
import java.beans.XMLDecoder
import java.io.ByteArrayInputStream

fun parseXml(input: String) {
    val xmlDecoder = XMLDecoder(ByteArrayInputStream(input.toByteArray()))
    val obj = xmlDecoder.readObject()
    xmlDecoder.close()
}
`
	flows := Analyze(code, "/app/XmlHandler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.xmldecoder.readobject" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for XMLDecoder.readObject()")
	}
}

// ---------- Moshi fromJson (CWE-502) ----------

func TestKotlin_MoshiFromJson(t *testing.T) {
	code := `
import com.squareup.moshi.Moshi
import com.squareup.moshi.JsonAdapter

fun parseUser(json: String) {
    val moshi = Moshi.Builder().build()
    val adapter = moshi.adapter(User::class.java)
    val user = adapter.fromJson(json)
    println(user)
}
`
	flows := Analyze(code, "/app/Api.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.moshi.fromjson" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for Moshi adapter.fromJson()")
	}
}

// ---------- Kryo (CWE-502) ----------

func TestKotlin_KryoReadObject(t *testing.T) {
	code := `
import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.io.Input

fun deserialize(data: ByteArray) {
    val kryo = Kryo()
    val input = Input(data)
    val obj = kryo.readObject(input, User::class.java)
}
`
	flows := Analyze(code, "/app/Serializer.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.kryo.readobject" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for Kryo.readObject()")
	}
}

func TestKotlin_KryoReadClassAndObject(t *testing.T) {
	code := `
import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.io.Input

fun deserializeUntyped(data: ByteArray) {
    val kryo = Kryo()
    val input = Input(data)
    val obj = kryo.readClassAndObject(input)
}
`
	flows := Analyze(code, "/app/Serializer.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkDeserialize && f.Sink.ID == "kotlin.kryo.readclassandobject" {
			found = true
		}
	}
	if !found {
		t.Error("Expected deserialization finding for Kryo.readClassAndObject()")
	}
}

// ---------- Spring sendRedirect (CWE-601) ----------

func TestKotlin_SpringSendRedirect(t *testing.T) {
	code := `
fun handler() {
    val url = readLine()
    response.sendRedirect(url)
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.spring.sendredirect" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for HttpServletResponse.sendRedirect()")
	}
}

// ---------- Spring RedirectView (CWE-601) ----------

func TestKotlin_SpringRedirectView(t *testing.T) {
	code := `
fun handler() {
    val target = readLine()
    return RedirectView(target)
}
`
	flows := Analyze(code, "/app/RedirectController.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Sink.ID == "kotlin.spring.redirectview" {
			found = true
		}
	}
	if !found {
		t.Error("Expected redirect finding for Spring RedirectView()")
	}
}

// ---------- JSch setCommand (CWE-78) ----------

func TestKotlin_JSchSetCommand(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    val channelExec = session.openChannel("exec") as ChannelExec
    channelExec.setCommand(cmd)
    channelExec.connect()
}
`
	flows := Analyze(code, "/app/SshClient.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Sink.ID == "kotlin.jsch.setcommand" {
			found = true
		}
	}
	if !found {
		t.Error("Expected command injection finding for ChannelExec.setCommand()")
	}
}
