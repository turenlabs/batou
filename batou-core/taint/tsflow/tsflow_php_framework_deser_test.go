package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP framework deserialization tests (CWE-502)
//
// Covers WordPress maybe_unserialize, Laravel Crypt::decrypt (CVE-2018-15133),
// Symfony/JMS Serializer->deserialize, and the PHP yaml extension's yaml_parse
// (!php/object tag).
// =========================================================================

func TestPHP_Deser_WordPress_MaybeUnserialize(t *testing.T) {
	code := `<?php
function handler() {
    $data = $_POST["data"];
    $obj = maybe_unserialize($data);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for $_POST -> maybe_unserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Deser_Laravel_CryptDecrypt(t *testing.T) {
	code := `<?php
function handler() {
    $cipher = $_GET["token"];
    $obj = Crypt::decrypt($cipher);
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for $_GET -> Crypt::decrypt() (CVE-2018-15133)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Deser_Symfony_SerializerDeserialize(t *testing.T) {
	code := `<?php
use Symfony\Component\Serializer\Serializer;

function handler($serializer) {
    $payload = $_POST["payload"];
    $obj = $serializer->deserialize($payload, "App\\Entity\\User", "json");
    return $obj;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for $_POST -> $serializer->deserialize()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestPHP_Deser_YamlParse(t *testing.T) {
	code := `<?php
function handler() {
    $yaml = $_POST["config"];
    $data = yaml_parse($yaml);
    return $data;
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialize flow for $_POST -> yaml_parse() (!php/object gadget)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Safe counterpart: calling the new framework sinks on a constant literal
// (not tainted) must NOT produce a deserialize flow. Regression guard that the
// new patterns don't match trivially.
func TestPHP_Deser_ConstantInput_NoFlow(t *testing.T) {
	code := `<?php
function handler() {
    $obj = maybe_unserialize("a:0:{}");
    $c = Crypt::decrypt("constant-cipher");
    $d = yaml_parse("- a\n- b\n");
}
?>`
	flows := Analyze(code, "/app/handler.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("no taint source present — framework deserialize sinks must not fire on constants")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
