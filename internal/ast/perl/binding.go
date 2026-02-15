// Package perl provides tree-sitter language bindings for Perl.
package perl

//#include "parser.h"
//const TSLanguage *tree_sitter_perl(void);
import "C"
import (
	"unsafe"

	sitter "github.com/smacker/go-tree-sitter"
)

// GetLanguage returns the tree-sitter Language for Perl.
func GetLanguage() *sitter.Language {
	ptr := unsafe.Pointer(C.tree_sitter_perl())
	return sitter.NewLanguage(ptr)
}
