package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Ruby iterator-block loop-variable seeding (recall FN).
//
// Ruby's dominant iteration idiom is a method-call-with-block
// (`coll.each { |x| ... }`), not a `for` statement. The for-loop seeding
// handlers (processPythonForLoop / processJSForOf / processEnhancedFor) never
// reach it, so the block parameter previously lost the receiver's taint and a
// user-controlled collection iterated into a sink produced zero flows. These
// tests cover the seeding fix in seedRubyBlockParams.

func TestRuby_EachDoBlock_Command(t *testing.T) {
	code := `
def handle(params)
    items = params[:items]
    items.each do |item|
        system(item)
    end
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for tainted collection -> each-do block param -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_EachBraceBlock_InlineSource_Command(t *testing.T) {
	code := `
def handle(params)
    params[:names].each { |n| system(n) }
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for inline source -> each-brace block param -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_MapBlock_Command(t *testing.T) {
	code := `
def handle(params)
    cmds = params[:cmds]
    cmds.map { |c| system(c) }
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for tainted collection -> map block param -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_EachWithIndex_MultiParam_SQL(t *testing.T) {
	// |val, i| — both block params derive from the tainted receiver; the
	// element `val` flows to a raw SQL sink.
	code := `
def handle(params)
    rows = params[:rows]
    rows.each_with_index do |val, i|
        ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE x = '#{val}'")
    end
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for tainted collection -> each_with_index element -> execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestRuby_SelectBlock_Command(t *testing.T) {
	code := `
def handle(params)
    args = params[:args]
    args.select { |a| system(a) }
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for tainted collection -> select block param -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control 1: a constant (non-tainted) collection must NOT seed taint
// into the block parameter, so no flow is produced.
func TestRuby_EachBlock_ConstantCollection_NoFlow(t *testing.T) {
	code := `
def handle
    items = ["ls", "pwd"]
    items.each do |item|
        system(item)
    end
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a flow for a constant (non-tainted) collection")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control 2: a non-iterator block method (`tap`) on a tainted receiver
// is NOT in the allowlist, so its block param is not seeded. (The receiver is
// the value itself; this guards the allowlist gating, not soundness.)
func TestRuby_NonIteratorBlock_NotSeeded(t *testing.T) {
	code := `
def handle(params)
    items = params[:items]
    other = ["safe"]
    other.tap { |x| system(x) }
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a flow: receiver is a constant and tap is not an iterator method")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
