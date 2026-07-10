package rubyast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
)

// rubyast_allowlist_guard.go recognises an ALLOWLIST / VALIDATION GUARD that
// constrains the method name passed to a dynamic dispatch (send / public_send /
// __send__), mirroring the Python eval-guard idea (rules.PyHasEvalGuard) for the
// Ruby dynamic-dispatch sink class (BATOU-RUBYAST-003).
//
// Real-world FP (smoke test, discourse-discourse): a dispatch whose method-name
// argument is checked against an allowlist on a preceding line —
//
//	if TopicsBulkAction.operations.exclude?(@operation[:type])
//	  raise Discourse::InvalidParameters.new(:operation)
//	end
//	send(@operation[:type])                       # constrained to a known set
//
//	return unless ALLOWED.include?(name)
//	public_send(name)
//
// is not arbitrary-method invocation: the value is provably one of a fixed set
// before it reaches the sink. The dispatch finding is a false positive.
//
// DESIGN PRINCIPLES (conservative — recall preservation is paramount):
//
//   - The guard must be an ALLOWLIST / VALIDATION predicate: a membership test
//     (`.include?` / `.exclude?` / `.member?`), a `has_*?` / `valid_*?` /
//     `respond_to?` predicate, or a strict-charset regex match. A bare presence
//     / truthiness check does NOT qualify.
//   - The guard must REFERENCE THE DISPATCHED VALUE: it must share an identifier
//     (or the same subscript key) with the method-name argument, so it
//     constrains THIS dispatch rather than some unrelated value.
//   - The guard must appear BEFORE the sink within the same enclosing method
//     body (a bounded intra-method scan), like the Python lookback.
//   - Suppresses ONLY the dynamic-dispatch finding. Nothing else changes.

// rubyDispatchGuarded reports whether a send/public_send/__send__ call `sink`
// is preceded, within its enclosing method, by an allowlist/validation guard
// that constrains the dispatched method name.
func rubyDispatchGuarded(sink *ast.Node, methodArg *ast.Node) bool {
	if sink == nil || methodArg == nil {
		return false
	}
	tokens := rubyValueTokens(methodArg)
	if len(tokens) == 0 {
		return false
	}
	body := rubyEnclosingMethodBody(sink)
	if body == nil {
		return false
	}
	sinkStart := sink.StartByte()

	guarded := false
	body.Walk(func(w *ast.Node) bool {
		if guarded {
			return false
		}
		// Only consider guards that appear textually before the sink.
		if w.StartByte() >= sinkStart {
			return true
		}
		if w.Type() == "call" && rubyCallIsAllowlistGuard(w, tokens) {
			guarded = true
			return false
		}
		return true
	})
	return guarded
}

// rubyValueTokens returns the identifier / symbol / subscript-key tokens that
// identify the dispatched value. For `@operation[:type]` it yields
// {"operation", "type"}; for `name` it yields {"name"}; for `:"#{post_type}_x"`
// it yields {"post_type"}. A guard must reference one of these.
func rubyValueTokens(arg *ast.Node) map[string]bool {
	set := make(map[string]bool)
	arg.Walk(func(w *ast.Node) bool {
		switch w.Type() {
		case "identifier", "constant":
			set[w.Text()] = true
		case "instance_variable":
			// @operation -> operation (so it matches a guard that names the same
			// receiver, e.g. `@operation[:type]`).
			set[strings.TrimLeft(w.Text(), "@")] = true
		case "simple_symbol", "hash_key_symbol":
			// :type -> type
			set[strings.TrimLeft(w.Text(), ":")] = true
		}
		return true
	})
	return set
}

// rubyEnclosingMethodBody returns the body node of the method / block enclosing
// node n. Walks up to the nearest `method`, `singleton_method`, or `do_block` /
// `block` and returns the whole construct (its subtree contains both the guard
// and the sink, in source order).
func rubyEnclosingMethodBody(n *ast.Node) *ast.Node {
	for _, anc := range n.Ancestors() {
		switch anc.Type() {
		case "method", "singleton_method", "do_block", "block":
			return anc
		}
	}
	return nil
}

// rubyCallIsAllowlistGuard reports whether a call node is an allowlist /
// validation predicate that references one of the dispatched-value tokens.
func rubyCallIsAllowlistGuard(call *ast.Node, tokens map[string]bool) bool {
	method, _ := rubyCallInfo(call)
	if !rubyIsAllowlistPredicateName(method) {
		return false
	}
	return rubyCallReferencesTokens(call, tokens)
}

// rubyIsAllowlistPredicateName reports whether a method name is an allowlist /
// validation predicate that constrains its argument to a known set: a
// membership test, a presence-in-set test, or a has_*? / valid_*? / allowed_*? /
// known_*? convention predicate. Deliberately EXCLUDES weak / generic
// predicates (`present?`, `any?`, `is_a?`, truthiness) which test shape or
// non-emptiness, not membership in an allowlist.
func rubyIsAllowlistPredicateName(name string) bool {
	switch name {
	case "include?", "exclude?", "member?", "respond_to?",
		"key?", "has_key?", "cover?", "in?":
		return true
	}
	lower := strings.ToLower(name)
	// has_*? / valid_*? / allowed_*? / known_*? convention predicates.
	if strings.HasSuffix(lower, "?") {
		if strings.HasPrefix(lower, "has_") || strings.HasPrefix(lower, "valid") ||
			strings.HasPrefix(lower, "allowed") || strings.HasPrefix(lower, "known") {
			return true
		}
	}
	return false
}

// rubyCallReferencesTokens reports whether any identifier / symbol / subscript
// key appearing in a call references one of the dispatched-value tokens.
func rubyCallReferencesTokens(call *ast.Node, tokens map[string]bool) bool {
	found := false
	call.Walk(func(w *ast.Node) bool {
		if found {
			return false
		}
		switch w.Type() {
		case "identifier", "constant":
			if tokens[w.Text()] {
				found = true
				return false
			}
		case "instance_variable":
			if tokens[strings.TrimLeft(w.Text(), "@")] {
				found = true
				return false
			}
		case "simple_symbol", "hash_key_symbol":
			if tokens[strings.TrimLeft(w.Text(), ":")] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
