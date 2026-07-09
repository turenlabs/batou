package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// ActiveRecord string-interpolation / string-concatenation SQLi (CWE-89).
//
// Verified recall gap (railsgoat users_controller.rb:29 —
// `User.where("id = '#{params[:user][:id]}'")[0]`): the canonical Rails SQLi
// shape produced only a regex-tier HINT (BATOU-FW-RAILS-006, conf 0.5) and NO
// dataflow-confirmed taint flow, because the `.where`/`.order` interpolation
// sinks carried ObjectType "ActiveRecord" — a receiver name no model class ever
// has (the receiver is `User`/`Post`/…). The sibling select/having/joins/group/
// from interpolation sinks already used ObjectType "" and fired; only .where and
// .order were anchored to the never-matching ObjectType.
//
// Fix: the AR raw-SQL-accepting query builders (where, where.not, order,
// reorder, pluck, exists?, find_by, calculate, lock) carry ObjectType "" with a
// PRECISE, weakSinkPatternOK-ENFORCED Pattern that requires a string literal
// containing `#{...}` interpolation OR a string concatenation — the exact
// discriminator between the unsafe raw-string form and the safe
// parameterized/hash/symbol/pure-literal forms. The Pattern is delimiter-aware
// so the common `where("col = '#{x}'")` (SQL single-quote inside a Ruby
// double-quoted string) is caught.

// arInterpFlow reports whether the Ruby code produces a SnkSQLQuery taint flow.
func arInterpFlow(t *testing.T, code string) bool {
	t.Helper()
	return hasTaintFlow(Analyze(code, "/app/models/user_query.rb", rules.LangRuby), taint.SnkSQLQuery)
}

// TestRubyAR_InterpolationSQLi_Fires is the load-bearing positive: each of the
// AR raw-SQL query builders fed a string-interpolated / concatenated tainted
// value must produce a dataflow-confirmed CWE-89 flow. Reverting the
// ruby_sinks.go ObjectType/Pattern change makes the where/order cases (and the
// added pluck/exists?/find_by/calculate/lock cases) fail.
func TestRubyAR_InterpolationSQLi_Fires(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// The exact railsgoat shape: SQL single-quote inside a Ruby
			// double-quoted string, source interpolated directly at the sink.
			name: "where-direct-railsgoat-shape",
			code: "def show(params)\n  User.where(\"id = '#{params[:user][:id]}'\")[0]\nend\n",
		},
		{
			name: "where-indirect",
			code: "def show(params)\n  uid = params[:id]\n  User.where(\"id = '#{uid}'\")\nend\n",
		},
		{
			name: "where-concat",
			code: "def show(params)\n  uid = params[:id]\n  User.where(\"id = '\" + uid + \"'\")\nend\n",
		},
		{
			name: "where-not-interp",
			code: "def show(params)\n  n = params[:name]\n  User.where.not(\"name = '#{n}'\")\nend\n",
		},
		{
			name: "order-interp",
			code: "def show(params)\n  col = params[:sort]\n  User.order(\"#{col} DESC\")\nend\n",
		},
		{
			name: "reorder-interp",
			code: "def show(params)\n  col = params[:sort]\n  User.reorder(\"#{col} ASC\")\nend\n",
		},
		{
			name: "pluck-interp",
			code: "def show(params)\n  col = params[:col]\n  User.pluck(\"#{col}\")\nend\n",
		},
		{
			name: "exists-interp",
			code: "def show(params)\n  c = params[:c]\n  User.exists?(\"name = '#{c}'\")\nend\n",
		},
		{
			name: "find_by-interp",
			code: "def show(params)\n  c = params[:c]\n  User.find_by(\"name = '#{c}'\")\nend\n",
		},
		{
			name: "calculate-interp",
			code: "def show(params)\n  c = params[:c]\n  User.calculate(:sum, \"#{c}\")\nend\n",
		},
		{
			name: "lock-interp",
			code: "def show(params)\n  c = params[:c]\n  User.lock(\"#{c}\").first\nend\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !arInterpFlow(t, tc.code) {
				t.Errorf("expected CWE-89 SnkSQLQuery flow for %s, got none", tc.name)
			}
		})
	}
}

// TestRubyAR_InterpolationSQLi_SafeFormsDoNotFire pins the FP contract: the safe
// AR forms that real Rails apps are full of must NOT produce a SnkSQLQuery flow.
// A regression here means the wildcard-ObjectType change started matching benign
// queries — the exact trap this Pattern is designed to avoid.
func TestRubyAR_InterpolationSQLi_SafeFormsDoNotFire(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// Parameterized placeholder + separate bind arg.
			name: "where-placeholder",
			code: "def show(params)\n  User.where(\"name = ?\", params[:name])\nend\n",
		},
		{
			// Named placeholder + hash bind arg.
			name: "where-named-placeholder",
			code: "def show(params)\n  User.where(\"name = :n\", n: params[:name])\nend\n",
		},
		{
			// Hash conditions — the idiomatic safe form.
			name: "where-hash",
			code: "def show(params)\n  User.where(name: params[:name])\nend\n",
		},
		{
			name: "where-not-hash",
			code: "def show(params)\n  User.where.not(name: params[:name])\nend\n",
		},
		{
			// Pure static literal, no taint at all.
			name: "where-pure-literal",
			code: "def show(params)\n  User.where(\"active = true\")\nend\n",
		},
		{
			// Static literal that happens to contain a quoted SQL string but no
			// interpolation/concatenation.
			name: "where-static-quoted",
			code: "def show(params)\n  User.where(\"name = 'admin'\")\nend\n",
		},
		{
			// order/pluck/find_by with a symbol/hash — the safe column forms.
			name: "order-symbol",
			code: "def show(params)\n  User.order(:created_at)\nend\n",
		},
		{
			name: "pluck-symbol",
			code: "def show(params)\n  User.pluck(:name)\nend\n",
		},
		{
			name: "find_by-hash",
			code: "def show(params)\n  User.find_by(id: params[:id])\nend\n",
		},
		{
			name: "exists-hash",
			code: "def show(params)\n  User.exists?(id: params[:id])\nend\n",
		},
		{
			// .to_i coercion neutralizes the interpolated value.
			name: "where-interp-to_i-sanitized",
			code: "def show(params)\n  User.where(\"id = #{params[:id].to_i}\")\nend\n",
		},
		{
			// connection.quote neutralizes the interpolated value.
			name: "where-interp-quote-sanitized",
			code: "def show(params)\n  q = ActiveRecord::Base.connection.quote(params[:name])\n  User.where(\"name = #{q}\")\nend\n",
		},
		{
			// sanitize_sql neutralizes the conditions array.
			name: "where-sanitize_sql",
			code: "def show(params)\n  c = ActiveRecord::Base.sanitize_sql([\"name = ?\", params[:name]])\n  User.where(c)\nend\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if arInterpFlow(t, tc.code) {
				t.Errorf("expected NO SnkSQLQuery flow for safe form %s, but a flow was reported", tc.name)
			}
		})
	}
}

// TestRubyAR_InlineImplicitParams pins the EXACT railsgoat shape: `params` is
// the Rails implicit accessor (not a method parameter) and the source is a
// nested subscript used INLINE inside the string interpolation at the sink, with
// no intervening local variable. This is what the railsgoat
// users_controller.rb:29 line looks like; it requires the findSourceInExpr Ruby
// string-interpolation recursion (not just the catalog ObjectType change).
func TestRubyAR_InlineImplicitParams(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			name: "where-inline-nested-implicit-params",
			code: "def update\n  user = User.where(\"id = '#{params[:user][:id]}'\")[0]\n  user\nend\n",
		},
		{
			name: "where-inline-single-implicit-params",
			code: "def update\n  User.where(\"id = '#{params[:id]}'\")\nend\n",
		},
		{
			name: "order-inline-implicit-params",
			code: "def index\n  User.order(\"#{params[:sort]} DESC\")\nend\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !arInterpFlow(t, tc.code) {
				t.Errorf("expected CWE-89 flow for inline implicit-params %s, got none", tc.name)
			}
		})
	}
}

// TestRubyAR_InterpBareNameNotSource pins the FP fix for the inline-interpolation
// recursion: a BARE local/instance/class variable or constant inside `#{...}`
// must NOT be resolved as a taint source. Such a name, if tainted, is already in
// the taint map (and caught by nodeIsTainted); resolving it via the bare-name
// fallback would collide with source METHOD names (a local `query` matching the
// PG/Mysql2 `query` DB-read source) and flag values sanitized in a helper the
// single-file walk can't see (Discourse `query = Search.ts_query(...)`).
func TestRubyAR_InterpBareNameNotSource(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// `query` is a local whose name collides with the `.query` DB source
			// method name; it is built by a (sanitizing) helper, so the bare name
			// must not be treated as a fresh source.
			name: "bare-local-named-query",
			code: "def search\n  query = Search.ts_query(term: @term)\n  scoped.where(\"data @@ #{query}\")\nend\n",
		},
		{
			name: "bare-instance-variable",
			code: "def search\n  scoped.where(\"data @@ #{@safe_fragment}\")\nend\n",
		},
		{
			name: "bare-constant",
			code: "def index\n  channels.order(\"LOWER(#{CHANNEL_NAME_SQL}) ASC\")\nend\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if arInterpFlow(t, tc.code) {
				t.Errorf("bare name in interpolation must not be a source for %s, but a flow was reported", tc.name)
			}
		})
	}
}

// TestRubyAR_NoReceiverTaintFP pins that the AR query-builder interpolation sinks
// fire only on a tainted STRING ARGUMENT, never on a tainted receiver relation.
// AR relations chain, so an earlier DB-read taints the whole receiver; a
// `.order("LOWER(#{CONST}) ASC")` interpolating a constant, or a parameterized
// `.where("... #{cond} ...", bind_hash)`, must stay clean even when the receiver
// is tainted. (Verified on Discourse topic_query.rb / search_chat_channels.rb.)
func TestRubyAR_NoReceiverTaintFP(t *testing.T) {
	cases := []struct {
		name string
		code string
	}{
		{
			// Receiver tainted by a prior .pluck; the where interpolates only a
			// constant and passes the bind hash separately (safe parameterized).
			name: "parameterized-where-tainted-receiver",
			code: "def list_topics\n  tag_ids = Tag.pluck(:id)\n  params_hash = { tag_ids: tag_ids }\n  rel = Topic.where(active: true)\n  rel.where(\"tt.tag_id IN (:tag_ids) AND #{1 > 0 ? \"x = 1\" : \"\"}\", params_hash)\nend\n",
		},
		{
			// Receiver tainted; order interpolates only a constant.
			name: "constant-order-tainted-receiver",
			code: "def index\n  names = User.pluck(:name)\n  rel = Channel.where(active: true)\n  rel.order(\"LOWER(channels.name) ASC\")\nend\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if arInterpFlow(t, tc.code) {
				t.Errorf("receiver-taint must not fire AR interpolation sink for %s, but a flow was reported", tc.name)
			}
		})
	}
}

// TestRubyAR_WhereInterp_PinsSink pins the specific sink ID firing on the
// railsgoat shape so a future catalog edit that silently drops the flow to a
// different (e.g. weaker) sink is caught.
func TestRubyAR_WhereInterp_PinsSink(t *testing.T) {
	code := "def show(params)\n  User.where(\"id = '#{params[:user][:id]}'\")[0]\nend\n"
	flows := Analyze(code, "/app/models/user_query.rb", rules.LangRuby)
	if !findSinkID(flows, "ruby.activerecord.where.interpolation") {
		t.Errorf("expected sink ruby.activerecord.where.interpolation; flows=%v", flows)
		for _, f := range flows {
			t.Logf("  sink=%s cat=%s conf=%.2f", f.Sink.ID, f.Sink.Category, f.Confidence)
		}
	}
}
