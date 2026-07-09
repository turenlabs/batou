package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// Interpreter inline-eval flags (python -c, perl -e, ruby -e, node -e/--eval,
// php -r) execute their argument as code in that language. A tainted shell
// variable interpolated into the eval string is arbitrary code execution
// (CWE-94), distinct from `sh -c` shell-command injection. Each case wires an
// untrusted `read` value into the interpreter's eval argument and asserts the
// matching SnkEval sink fires. The `read` builtin is the canonical
// tsflow-native shell source.
func TestShellInterpreterEvalSinks_Positive(t *testing.T) {
	cases := []struct {
		name   string
		code   string
		sinkID string
	}{
		{
			name:   "python3 -c inline program",
			code:   "read name\npython3 -c \"import os; os.system('echo ' + '$name')\"\n",
			sinkID: "shell.code.python_c",
		},
		{
			name:   "python -c with flags before -c",
			code:   "read code\npython -B -c \"print('$code')\"\n",
			sinkID: "shell.code.python_c",
		},
		{
			name:   "perl -e inline program",
			code:   "read payload\nperl -e \"system('$payload')\"\n",
			sinkID: "shell.code.perl_e",
		},
		{
			name:   "ruby -e inline program",
			code:   "read snippet\nruby -e \"eval('$snippet')\"\n",
			sinkID: "shell.code.ruby_e",
		},
		{
			name:   "node -e inline program",
			code:   "read js\nnode -e \"eval('$js')\"\n",
			sinkID: "shell.code.node_eval",
		},
		{
			name:   "node --eval inline program",
			code:   "read js\nnode --eval \"console.log('$js')\"\n",
			sinkID: "shell.code.node_eval",
		},
		{
			name:   "php -r inline program",
			code:   "read p\nphp -r \"eval('$p');\"\n",
			sinkID: "shell.code.php_r",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flows := analyzeShellScript(tc.code)
			if !shellFlowHasSink(flows, tc.sinkID, taint.SnkEval) {
				t.Errorf("expected flow to sink %q (%s); got %d flows: %+v",
					tc.sinkID, taint.SnkEval, len(flows), flowSummaries(flows))
			}
		})
	}
}

// A constant interpreter eval string with no tainted argument must not produce
// a code-eval flow, even when an unrelated `read` source exists in the script.
func TestShellInterpreterEvalSinks_NegativeConstant(t *testing.T) {
	code := "read x\n" +
		"python3 -c \"print('hello')\"\n" +
		"perl -e \"print 42\"\n" +
		"ruby -e \"puts :ok\"\n" +
		"node -e \"console.log(1)\"\n" +
		"php -r \"echo 1;\"\n" +
		"echo \"$x\"\n"
	flows := analyzeShellScript(code)
	for _, f := range flows {
		switch f.Sink.ID {
		case "shell.code.python_c", "shell.code.perl_e", "shell.code.ruby_e",
			"shell.code.node_eval", "shell.code.php_r":
			t.Errorf("constant eval string must not fire code-eval sink %q; got: %+v",
				f.Sink.ID, flowSummaries(flows))
		}
	}
}
