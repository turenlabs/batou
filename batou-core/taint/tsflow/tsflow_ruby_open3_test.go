package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Family-completion tests for the Open3 command-execution methods that were
// previously unmodeled: capture2e, popen2, popen2e, and the pipeline_*
// variants. Each spawns a subprocess with the same shell-injection semantics
// as the already-covered capture2/capture3/popen3/pipeline entries.

func TestRuby_Open3Capture2e_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    output, status = Open3.capture2e(cmd)
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.capture2e")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Open3Popen2_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    Open3.popen2(cmd) do |stdin, stdout, wait_thr|
        output = stdout.read
    end
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.popen2")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Open3Popen2e_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    Open3.popen2e(cmd) do |stdin, stdout_err, wait_thr|
        output = stdout_err.read
    end
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.popen2e")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Open3PipelineStart_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    wait_thrs = Open3.pipeline_start(cmd, "wc -l")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.pipeline_start")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Open3PipelineR_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    last_stdout, wait_thrs = Open3.pipeline_r(cmd, "sort")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.pipeline_r")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Open3PipelineW_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    first_stdin, wait_thrs = Open3.pipeline_w(cmd, "tee out.txt")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.pipeline_w")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_Open3PipelineRW_CommandInjection(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    cmd = params[:cmd]
    first_stdin, last_stdout, wait_thrs = Open3.pipeline_rw(cmd, "grep foo")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for params -> Open3.pipeline_rw")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative control: a constant command string through Open3.capture2e must NOT
// produce a command-injection flow.
func TestRuby_Open3Capture2e_ConstantSafe(t *testing.T) {
	code := `
require 'open3'
def handler(params)
    output, status = Open3.capture2e("uptime")
end
`
	flows := Analyze(code, "/app/handler.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect command injection flow for constant Open3.capture2e")
	}
}
