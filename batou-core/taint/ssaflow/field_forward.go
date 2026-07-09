package ssaflow

import (
	"go/token"

	"golang.org/x/tools/go/ssa"
)

// field_forward.go implements store-to-load forwarding for memory-resident
// taint through LOCAL aggregates (structs and arrays/slices declared in the
// function under analysis).
//
// Why this exists
// ---------------
// The SSA builder runs the mem2reg lift pass (NaiveForm is OFF in buildSSA),
// but go/ssa's lifter ONLY promotes scalar Allocs whose every referrer is a
// direct load/store (lift.go:liftAlloc). The moment an Alloc's address is
// taken by a FieldAddr (`&o.F`) or IndexAddr (`&a[i]`) — i.e. the local is a
// struct or array — the Alloc is declared non-liftable and stays in memory.
//
// So a function like
//
//	func H(r *http.Request) {
//	    var o O
//	    o.F = r.URL.Query().Get("q")   // Store t4 -> &o.F
//	    db.Exec(o.F)                   // Load *(&o.F)
//	}
//
// lowers to (abridged):
//
//	t0 = local O (o)        // Alloc, NOT lifted (FieldAddr referrer)
//	...
//	t4 = (net/url.Values).Get(...)
//	t5 = &t0.F [#0]         // FieldAddr (store address)
//	*t5 = t4                // Store
//	t8 = &t0.F [#0]         // FieldAddr (load address) — distinct SSA value!
//	t9 = *t8                // Load
//	(*sql.DB).Exec(_, t9)
//
// The backward def-use walk in reaches()/reachesAnyParam()/... recurses from
// the load t9 into its only operand t8 (the FieldAddr), then into t0 (the
// Alloc). t0 is not a source param, so the chain dies. The Store `*t5 = t4`
// is NEVER visited: the load and the store share an ADDRESS (both FieldAddr
// off t0 field #0) but there is no SSA operand edge from the load to the
// store. This file recovers that edge.
//
// What it does
// ------------
// Given a load (UnOp '*'), resolve its address to a (root, access-path) pair
// where root is the underlying Alloc and the access-path is the sequence of
// field/index selectors. Then scan the SAME function for Store instructions
// whose address resolves to an ALIASING (root, access-path) and surface each
// Store.Val as an extra backward data dependency. The existing walkers then
// recurse into those stored values exactly as they would any operand, so a
// tainted RHS reaches the load transparently.
//
// Precision discipline
// --------------------
//   - Root identity: forwarding is gated on the load and store sharing the
//     SAME root Alloc by pointer identity. `o.F` never forwards from `p.F`.
//   - Field discrimination: struct selectors must match by field index, so
//     `o.G = src; sink(o.F)` does NOT fire — the canonical no-FP sibling.
//   - Index-insensitive on arrays/slices: `a[i]` selectors match any index
//     (whole-container), mirroring the documented whole-pointee approach in
//     pointer_arg.go. Sound for FN; the modest over-approximation matches
//     how every taint engine in this codebase treats collections.
//   - Local roots only: the root must be an *ssa.Alloc in the function being
//     walked. Stores through parameters / globals / returned pointers are
//     out of scope here (pointer_arg.go and the param/global machinery cover
//     those), so we never reach across the function boundary from this pass.
//   - Flow-insensitive (standard for taint): every aliasing store is a
//     candidate, regardless of program order. A tainted store followed by a
//     constant overwrite to the same field is a theoretical FP, but that is
//     the same over-approximation astflow/tsflow already make and is vanish-
//     ingly rare in real handler code.

// fieldSelector is one step in an access path: either a struct field
// (isIndex=false, field=index) or a collection element (isIndex=true, field
// ignored — index-insensitive).
type fieldSelector struct {
	isIndex bool
	field   int
}

// addrPath resolves an address-producing SSA value to its underlying root
// (typically an *ssa.Alloc) plus the selector chain from the root to addr.
// The chain is returned root-first (outermost selector last), matching the
// order in which we will compare two paths element by element.
//
// Returns ok=false when the address is not a FieldAddr/IndexAddr chain
// bottoming out in a stable root we can compare by identity (e.g. addresses
// produced by calls, conversions, or pointer arithmetic we don't model).
func addrPath(addr ssa.Value) (root ssa.Value, path []fieldSelector, ok bool) {
	cur := addr
	// Build the chain leaf-first, then reverse to root-first.
	var rev []fieldSelector
	for hops := 0; hops < 32; hops++ {
		switch n := cur.(type) {
		case *ssa.FieldAddr:
			rev = append(rev, fieldSelector{isIndex: false, field: n.Field})
			cur = n.X
		case *ssa.IndexAddr:
			rev = append(rev, fieldSelector{isIndex: true})
			cur = n.X
		default:
			// Reached the root. Two shapes are stable, comparable-by-
			// identity roots for store-forwarding:
			//   - *ssa.Alloc: a local var/temp (struct, array, scalar).
			//   - *ssa.Global: a package-level var. A `g = src` store and
			//     a `g` load in the same function lower to a Store/Load
			//     against the SAME *ssa.Global value, so identity holds.
			//     Stdlib globals are still filtered upstream by
			//     isUntaintableSSAValue (checked before recursion in every
			//     walker), so this never resurrects http.StatusBadRequest
			//     and friends — only app-defined globals can carry taint.
			// Anything else (parameter pointers, call results, pointer
			// arithmetic) is out of scope here and handled by other passes.
			switch cur.(type) {
			case *ssa.Alloc, *ssa.Global:
				// ok
			default:
				return nil, nil, false
			}
			// Reverse rev into root-first order.
			path = make([]fieldSelector, len(rev))
			for i := range rev {
				path[len(rev)-1-i] = rev[i]
			}
			return cur, path, true
		}
	}
	return nil, nil, false
}

// pathsAlias reports whether two access paths refer to the same memory cell
// for store-to-load forwarding. Roots must be identical by pointer; selector
// chains must match step-for-step. Index selectors match any index selector
// (index-insensitive); a field selector matches only the same field number.
// A struct field and a collection index at the same depth never alias.
func pathsAlias(rootA ssa.Value, pa []fieldSelector, rootB ssa.Value, pb []fieldSelector) bool {
	if rootA != rootB {
		return false
	}
	if len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		if pa[i].isIndex != pb[i].isIndex {
			return false
		}
		if !pa[i].isIndex && pa[i].field != pb[i].field {
			return false
		}
	}
	return true
}

// storeForwardedValues returns the set of values stored into a memory cell
// that aliases the cell loaded by v, when v is a load off a local aggregate.
// These are returned so the backward walkers can treat them as additional
// data dependencies of the load. Returns nil for any value that is not such
// a load, or whose address path cannot be resolved to a local Alloc — in
// which case the caller's behaviour is unchanged.
func storeForwardedValues(v ssa.Value) []ssa.Value {
	load, ok := v.(*ssa.UnOp)
	if !ok || load.Op != token.MUL {
		return nil
	}
	root, loadPath, ok := addrPath(load.X)
	if !ok {
		return nil
	}
	// The root Alloc tells us the enclosing function; scan its blocks for
	// aliasing stores. (load is an Instruction, so Parent() is available,
	// but routing through the Alloc keeps us robust if load is detached.)
	fn := load.Parent()
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	var out []ssa.Value
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			st, ok := instr.(*ssa.Store)
			if !ok || st.Val == nil {
				continue
			}
			sRoot, sPath, ok := addrPath(st.Addr)
			if !ok {
				continue
			}
			if pathsAlias(root, loadPath, sRoot, sPath) {
				out = append(out, st.Val)
			}
		}
	}
	return out
}
