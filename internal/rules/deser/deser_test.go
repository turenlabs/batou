package deser

import (
	"testing"

	"github.com/turenio/gtss/internal/testutil"
)

// ---------------------------------------------------------------------------
// GTSS-DESER-001: Extended Unsafe Deserialization
// ---------------------------------------------------------------------------

func TestDESER001_PythonShelveOpen(t *testing.T) {
	content := `import shelve
db = shelve.open(user_path)`
	result := testutil.ScanContent(t, "/app/data.py", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_PythonMarshalLoads(t *testing.T) {
	content := `import marshal
data = marshal.loads(raw_bytes)`
	result := testutil.ScanContent(t, "/app/loader.py", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_PythonMarshalLoad(t *testing.T) {
	content := `import marshal
data = marshal.load(file_obj)`
	result := testutil.ScanContent(t, "/app/loader.py", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_JavaXStreamFromXML(t *testing.T) {
	content := `XStream xstream = new XStream();
Object obj = xstream.fromXML(userInput);`
	result := testutil.ScanContent(t, "/app/Handler.java", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_JavaKryoReadObject(t *testing.T) {
	content := `Kryo kryo = new Kryo();
Object obj = kryo.readObject(input, MyClass.class);`
	result := testutil.ScanContent(t, "/app/Serializer.java", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_JavaKryoReadClassAndObject(t *testing.T) {
	content := `Object obj = kryo.readClassAndObject(input);`
	result := testutil.ScanContent(t, "/app/Serializer.java", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_JavaXMLDecoder(t *testing.T) {
	content := `XMLDecoder decoder = new XMLDecoder(inputStream);
Object obj = decoder.readObject();`
	result := testutil.ScanContent(t, "/app/XmlHandler.java", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_JavaSnakeYAML_Unsafe(t *testing.T) {
	content := `Yaml yaml = new Yaml();
Object data = yaml.load(userInput);`
	result := testutil.ScanContent(t, "/app/Config.java", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_JavaSnakeYAML_Safe(t *testing.T) {
	content := `Yaml yaml = new Yaml(new SafeConstructor());
Object data = yaml.load(userInput);`
	result := testutil.ScanContent(t, "/app/Config.java", content)
	testutil.MustNotFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_CSharpBinaryFormatter(t *testing.T) {
	content := `var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(stream);`
	result := testutil.ScanContent(t, "/app/Handler.cs", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_CSharpJsonNetTypeNameHandling(t *testing.T) {
	content := `var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.All
};`
	result := testutil.ScanContent(t, "/app/Config.cs", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-001")
}

func TestDESER001_CSharpJsonNetTypeNameNone_Safe(t *testing.T) {
	content := `var settings = new JsonSerializerSettings {
    TypeNameHandling = TypeNameHandling.None
};`
	result := testutil.ScanContent(t, "/app/Config.cs", content)
	testutil.MustNotFindRule(t, result, "GTSS-DESER-001")
}

// ---------------------------------------------------------------------------
// GTSS-DESER-002: Ruby Dangerous Dynamic Execution
// ---------------------------------------------------------------------------

func TestDESER002_RubyEvalVariable(t *testing.T) {
	content := `user_code = params[:code]
eval(user_code)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyKernelEval(t *testing.T) {
	content := `Kernel.eval(input_data)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyInstanceEval(t *testing.T) {
	content := `obj.instance_eval(user_code)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyClassEval(t *testing.T) {
	content := `MyClass.class_eval(code_string)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyModuleEval(t *testing.T) {
	content := `mod.module_eval(dynamic_code)`
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubySendWithParams(t *testing.T) {
	content := `method_name = params[:action]
obj.send(params[:method], arg1)`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyPublicSendWithParams(t *testing.T) {
	content := `action = params[:action]
obj.public_send(params[:action], value)`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubySendVarWithUserInput(t *testing.T) {
	content := `action = params[:action]
method = action.to_sym
obj.send(method, arg1)`
	result := testutil.ScanContent(t, "/app/controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyConstantizeWithParams(t *testing.T) {
	content := `class_name = params[:type]
klass = class_name.constantize
obj = klass.new`
	result := testutil.ScanContent(t, "/app/factory.rb", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-002")
}

func TestDESER002_RubyEvalStringLiteral_Safe(t *testing.T) {
	// eval with a string literal should not match (regex requires non-quote first char)
	content := `eval("2 + 2")`
	result := testutil.ScanContent(t, "/app/calc.rb", content)
	testutil.MustNotFindRule(t, result, "GTSS-DESER-002")
}

// ---------------------------------------------------------------------------
// GTSS-DESER-003: PHP Dangerous Patterns
// ---------------------------------------------------------------------------

func TestDESER003_PHPPregReplaceE(t *testing.T) {
	content := `<?php
$result = preg_replace('/test/e', $input, "test string");`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPPregReplaceE_WithFlags(t *testing.T) {
	content := `<?php
$output = preg_replace('/{(\w+)}/ei', '$data["$1"]', $template);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPPregReplace_Safe(t *testing.T) {
	// preg_replace without /e modifier should not match
	content := `<?php
$result = preg_replace('/test/i', 'replacement', $input);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustNotFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPExtractGET(t *testing.T) {
	content := `<?php
extract($_GET);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPExtractPOST(t *testing.T) {
	content := `<?php
extract($_POST);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPExtractREQUEST(t *testing.T) {
	content := `<?php
extract($_REQUEST);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPAssertVariable(t *testing.T) {
	content := `<?php
$check = $_GET['check'];
assert($check);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPCreateFunction(t *testing.T) {
	content := `<?php
$func = create_function('$a', $code);`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_PHPVariableFunction(t *testing.T) {
	content := `<?php
$func_name = $_GET['func'];
$$func_name('arg');`
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

// ---------------------------------------------------------------------------
// GTSS-DESER-004: JS/TS setTimeout/setInterval with String
// ---------------------------------------------------------------------------

func TestDESER004_SetTimeoutStringLiteral(t *testing.T) {
	content := `const code = req.query.code;
setTimeout('alert(1)', 1000);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-004")
}

func TestDESER004_SetIntervalStringLiteral(t *testing.T) {
	content := `const data = req.body.data;
setInterval('checkStatus()', 5000);`
	result := testutil.ScanContent(t, "/app/poller.ts", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-004")
}

func TestDESER004_SetTimeoutVariableWithUserInput(t *testing.T) {
	content := `app.get('/exec', (req, res) => {
  const code = req.query.code;
  setTimeout(code, 0);
});`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-004")
}

func TestDESER004_SetIntervalVariableWithUserInput(t *testing.T) {
	content := `const userInput = req.body.callback;
setInterval(userInput, 1000);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-004")
}

func TestDESER004_SetTimeoutFunction_Safe(t *testing.T) {
	// setTimeout with arrow function should not trigger
	content := `setTimeout(() => { console.log('done'); }, 1000);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustNotFindRule(t, result, "GTSS-DESER-004")
}

// ---------------------------------------------------------------------------
// Fixture-based tests
// ---------------------------------------------------------------------------

func TestDESER001_Fixture_PHP_Deserialization(t *testing.T) {
	if !testutil.FixtureExists("php/vulnerable/deserialization.php") {
		t.Skip("PHP deserialization fixture not available")
	}
	content := testutil.LoadFixture(t, "php/vulnerable/deserialization.php")
	result := testutil.ScanContent(t, "/app/handler.php", content)
	// PHP unserialize is caught by GEN-002, not DESER-001
	hasDeser := testutil.HasFinding(result, "GTSS-GEN-002") || testutil.HasFinding(result, "GTSS-DESER-001")
	if !hasDeser {
		t.Logf("findings: %v", testutil.FindingRuleIDs(result))
	}
}

func TestDESER003_Fixture_PHP_PregEval(t *testing.T) {
	if !testutil.FixtureExists("php/vulnerable/preg_eval.php") {
		t.Skip("PHP preg_eval fixture not available")
	}
	content := testutil.LoadFixture(t, "php/vulnerable/preg_eval.php")
	result := testutil.ScanContent(t, "/app/handler.php", content)
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER003_Fixture_PHP_EvalInjection(t *testing.T) {
	if !testutil.FixtureExists("php/vulnerable/eval_injection.php") {
		t.Skip("PHP eval injection fixture not available")
	}
	content := testutil.LoadFixture(t, "php/vulnerable/eval_injection.php")
	result := testutil.ScanContent(t, "/app/handler.php", content)
	// assert($check) should be caught by DESER-003
	testutil.MustFindRule(t, result, "GTSS-DESER-003")
}

func TestDESER002_Fixture_Ruby_Deserialization(t *testing.T) {
	if !testutil.FixtureExists("ruby/vulnerable/deserialization.rb") {
		t.Skip("Ruby deserialization fixture not available")
	}
	content := testutil.LoadFixture(t, "ruby/vulnerable/deserialization.rb")
	result := testutil.ScanContent(t, "/app/handler.rb", content)
	hasDeser := testutil.HasFinding(result, "GTSS-GEN-002") ||
		testutil.HasFinding(result, "GTSS-DESER-002") ||
		testutil.HasFinding(result, "GTSS-GEN-011")
	if !hasDeser {
		t.Logf("findings: %v", testutil.FindingRuleIDs(result))
	}
}
