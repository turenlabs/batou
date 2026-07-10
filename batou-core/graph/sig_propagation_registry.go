// Per-language adapter registry for the generic multi-hop fixpoint (#37).
//
// Each genericLangPropagator wires one cross-file language into
// propagateForGenericCaller. The adapter is the entire per-language
// surface: a call-site discovery closure (over the language's existing
// findXCallSitesIndexed + per-pass cache), the leaf sink/return producers,
// and the language set used for the same-language lift gate.
//
// genericPropagatorPass bundles a freshly-allocated per-pass parse cache
// with its adapter so PropagateSignaturesAcrossCallgraph can build them all
// once at the top of a pass and dispatch by language inside the loop. This
// preserves the parse-once-per-file performance contract the Python/JS
// caches already provide.
package graph

import "github.com/turenlabs/batou-rules/rules"

// genericPropagatorPass is one language adapter bound to its per-pass parse
// cache for a single PropagateSignaturesAcrossCallgraph invocation.
type genericPropagatorPass struct {
	prop  *genericLangPropagator
	cache interface{}
}

// run executes the generic propagation for one caller under this pass's
// adapter and cache.
func (gp genericPropagatorPass) run(cg *CallGraph, caller *FuncNode, fileContents map[string]string) int {
	return propagateForGenericCaller(cg, caller, fileContents, gp.prop, gp.cache)
}

// newGenericPropagatorPasses builds one genericPropagatorPass per
// generalized language, each with a fresh per-pass parse cache. Returns a
// map keyed by every FuncNode.Language the passes own, so the fixpoint can
// dispatch with a single map lookup. The C-family pair (LangC, LangCPP)
// shares one pass and is registered under both keys.
//
// Go, Python, and JavaScript/TypeScript are deliberately ABSENT here: they
// keep their bespoke propagateFor<Lang>Caller branches in
// PropagateSignaturesAcrossCallgraph (Go uses regex call discovery, not an
// indexed cache; Py/JS predate this generalization and stay unchanged so
// their multi-hop behaviour is byte-for-byte preserved).
func newGenericPropagatorPasses() map[rules.Language]genericPropagatorPass {
	passes := []genericPropagatorPass{
		newCSharpPropagatorPass(),
		newSwiftPropagatorPass(),
		newPHPPropagatorPass(),
		newRubyPropagatorPass(),
		newRustPropagatorPass(),
		newKotlinPropagatorPass(),
		newGroovyPropagatorPass(),
		newPerlPropagatorPass(),
		newShellPropagatorPass(),
		newLuaPropagatorPass(),
		newCPPPropagatorPass(),
	}
	byLang := map[rules.Language]genericPropagatorPass{}
	for _, gp := range passes {
		for _, l := range gp.prop.langs {
			byLang[l] = gp
		}
	}
	return byLang
}

// --- Per-language adapter constructors ---------------------------------
//
// Each constructor allocates the language's per-pass parse cache and wraps
// its findXCallSitesIndexed + producers in the generic adapter. The
// findCallSites closure type-asserts the opaque cache back to its concrete
// type and flattens the concrete call-site slice into []genericCallSite.

func newCSharpPropagatorPass() genericPropagatorPass {
	cache := newCSharpCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangCSharp},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findCSharpCallSitesIndexed(c.(*csharpCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureCSharpCalleeSinks,
			ensureReturns: ensureCSharpCalleeReturns,
		},
	}
}

func newSwiftPropagatorPass() genericPropagatorPass {
	cache := newSwiftCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangSwift},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findSwiftCallSitesIndexed(c.(*swiftCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureSwiftCalleeSinks,
			ensureReturns: ensureSwiftCalleeReturns,
		},
	}
}

func newPHPPropagatorPass() genericPropagatorPass {
	cache := newPHPCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangPHP},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findPHPCallSitesIndexed(c.(*phpCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensurePHPCalleeSinks,
			ensureReturns: ensurePHPCalleeReturns,
		},
	}
}

func newRubyPropagatorPass() genericPropagatorPass {
	cache := newRubyCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangRuby},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findRubyCallSitesIndexed(c.(*rubyCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks: ensureRubyCalleeSinks,
			// Ruby's walker does not yet produce tainted returns; sink-lift
			// only. ensureReturns nil → return-lift is a no-op (callees
			// arrive with empty TaintedReturns, the loop skips them).
			ensureReturns: nil,
		},
	}
}

func newRustPropagatorPass() genericPropagatorPass {
	cache := newRustCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangRust},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findRustCallSitesIndexed(c.(*rustCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureRustCalleeSinks,
			ensureReturns: ensureRustCalleeReturns,
		},
	}
}

func newKotlinPropagatorPass() genericPropagatorPass {
	cache := newKotlinCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangKotlin},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findKotlinCallSitesIndexed(c.(*kotlinCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureKotlinCalleeSinks,
			ensureReturns: ensureKotlinCalleeReturns,
		},
	}
}

func newGroovyPropagatorPass() genericPropagatorPass {
	cache := newGroovyCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangGroovy},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findGroovyCallSitesIndexed(c.(*groovyCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureGroovyCalleeSinks,
			ensureReturns: ensureGroovyCalleeReturns,
		},
	}
}

func newPerlPropagatorPass() genericPropagatorPass {
	cache := newPerlCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangPerl},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findPerlCallSitesIndexed(c.(*perlCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensurePerlCalleeSinks,
			ensureReturns: ensurePerlCalleeReturns,
		},
	}
}

func newShellPropagatorPass() genericPropagatorPass {
	cache := newShellCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangShell},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findShellCallSitesIndexed(c.(*shellCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureShellCalleeSinks,
			ensureReturns: ensureShellCalleeReturns,
		},
	}
}

func newLuaPropagatorPass() genericPropagatorPass {
	cache := newLuaCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			langs: []rules.Language{rules.LangLua},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findLuaCallSitesIndexed(c.(*luaCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureLuaCalleeSinks,
			ensureReturns: ensureLuaCalleeReturns,
		},
	}
}

func newCPPPropagatorPass() genericPropagatorPass {
	cache := newCPPCallIndexCache()
	return genericPropagatorPass{
		cache: cache,
		prop: &genericLangPropagator{
			// C and C++ share one walker; both languages match for the lift
			// gate, mirroring the cross-file walk dispatch (LangC, LangCPP).
			langs: []rules.Language{rules.LangC, rules.LangCPP},
			findCallSites: func(c interface{}, content string, caller *FuncNode, callee string) []genericCallSite {
				sites := findCPPCallSitesIndexed(c.(*cppCallIndexCache), content, caller, callee)
				out := make([]genericCallSite, len(sites))
				for i, s := range sites {
					out[i] = genericCallSite(s)
				}
				return out
			},
			ensureSinks:   ensureCPPCalleeSinks,
			ensureReturns: ensureCPPCalleeReturns,
		},
	}
}
