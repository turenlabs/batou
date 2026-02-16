package ast

import "github.com/turenlabs/batou/internal/rules"

// TreeFromContext extracts the *Tree from a ScanContext's Tree field.
// Returns nil if the field is nil or not a *Tree.
func TreeFromContext(sctx *rules.ScanContext) *Tree {
	if sctx == nil || sctx.Tree == nil {
		return nil
	}
	t, _ := sctx.Tree.(*Tree)
	return t
}
