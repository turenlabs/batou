package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Ruby — instance-variable (@ivar) and attribute-setter (obj.attr=) LHS
// taint propagation (CWE-78 command injection).
//
// Rails controllers routinely stash request data on instance variables
// (`@q = params[:q]`) that a later action / before_action / helper then
// feeds into a sink. Tree-sitter exposes `@q` as an `instance_variable`
// node (not an `identifier`), so the tsflow walker previously dropped the
// assignment LHS and the flow was invisible to dataflow. These tests lock
// in @ivar + attribute-setter LHS extraction and the field-sensitive read.
// =========================================================================

func TestRuby_IVar_CommandInjection(t *testing.T) {
	code := `
class HomeController < ApplicationController
  def index
    @q = params[:q]
    system(@q)
  end
end
`
	flows := Analyze(code, "/app/controllers/home_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow params[:q] -> @q -> system(@q)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestRuby_IVar_StringInterpolationCommandInjection(t *testing.T) {
	code := `
class HomeController < ApplicationController
  def index
    @host = params[:host]
    system("ping -c 1 #{@host}")
  end
end
`
	flows := Analyze(code, "/app/controllers/home_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow params[:host] -> @host -> system interpolation")
	}
}

func TestRuby_AttrSetter_CommandInjection(t *testing.T) {
	code := `
class HomeController < ApplicationController
  def show
    obj = Cmd.new
    obj.cmd = params[:c]
    system(obj.cmd)
  end
end
`
	flows := Analyze(code, "/app/controllers/home_controller.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow params[:c] -> obj.cmd -> system(obj.cmd)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Field sensitivity: assigning a tainted value to obj.cmd must NOT taint the
// sibling field obj.safe. Reading obj.safe at a sink stays clean.
func TestRuby_AttrSetter_SiblingFieldNotTainted(t *testing.T) {
	code := `
class HomeController < ApplicationController
  def show
    obj = Cmd.new
    obj.cmd = params[:c]
    obj.safe = "ls -la"
    system(obj.safe)
  end
end
`
	flows := Analyze(code, "/app/controllers/home_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("sibling field obj.safe must not be tainted by obj.cmd = params[:c]")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Constant-assigned @ivar must NOT produce a taint flow (precision: the AST
// analyzer still flags the structural system() call, but no dataflow exists).
func TestRuby_IVar_ConstantNotTainted(t *testing.T) {
	code := `
class HomeController < ApplicationController
  def index
    @q = "ls -la"
    system(@q)
  end
end
`
	flows := Analyze(code, "/app/controllers/home_controller.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("constant-assigned @q must not produce a command-injection taint flow")
	}
}
