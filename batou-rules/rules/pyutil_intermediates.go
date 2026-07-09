package rules

import (
	"regexp"
	"strings"
)

// pyFirstIntermediateVar extracts the first "local intermediate" variable
// referenced in a Python RHS expression. Used by PyLastAssignmentIsSafe to
// recursively walk indirection chains the OWASP Python benchmark uses, e.g.:
//
//	tmp = base64.b64encode(param.encode('utf-8'))
//	bar = base64.b64decode(tmp).decode('utf-8')          # intermediate=tmp
//	bar = superstring[len('20259'):len(superstring)-5]   # intermediate=superstring
//	bar = string40799[4:-17]                             # intermediate=string40799
//	bar = lst[0]                                         # intermediate=lst
//
// Returns "" when the RHS contains only literals / built-in / well-known
// non-local names. The function is intentionally conservative: callers use
// it as a hint to recursively re-check, so over-extraction (false-positive
// taint) is more harmful than under-extraction.
func pyFirstIntermediateVar(rhs string) string {
	rhs = strings.TrimSpace(rhs)
	if rhs == "" {
		return ""
	}
	// Skip dict-access expressions — these are handled separately via
	// pyDictAccess + PyDictKeyIsSafe (per-key resolution).
	if pyDictAccess.MatchString(rhs) {
		return ""
	}
	// Skip configparser .get() — handled separately via pyConfigGet.
	if pyConfigGet.MatchString(rhs) {
		return ""
	}
	// Tokenize and pick the first identifier that isn't a built-in,
	// keyword, stdlib module name, or string literal artefact.
	tokens := pyIdent.FindAllString(rhs, -1)
	for _, tok := range tokens {
		if pyBuiltinOrStdlib[tok] {
			continue
		}
		// Skip pure-numeric tokens (e.g. '49441' is captured by pyIdent? no
		// — pyIdent starts with a letter or _).
		return tok
	}
	return ""
}

// pyIdent matches a Python identifier.
var pyIdent = regexp.MustCompile(`[A-Za-z_]\w*`)

// pyBuiltinOrStdlib is a curated set of identifiers that should NOT be
// considered "local intermediates" — built-ins, common stdlib names,
// well-known framework objects, and primitive method names.
var pyBuiltinOrStdlib = map[string]bool{
	// Built-in funcs / types
	"True": true, "False": true, "None": true,
	"int": true, "str": true, "float": true, "bool": true, "bytes": true,
	"list": true, "dict": true, "set": true, "tuple": true, "frozenset": true,
	"len": true, "range": true, "enumerate": true, "zip": true, "map": true,
	"filter": true, "sorted": true, "reversed": true, "iter": true, "next": true,
	"any": true, "all": true, "sum": true, "min": true, "max": true, "abs": true,
	"print": true, "open": true, "input": true, "isinstance": true, "type": true,
	// stdlib modules commonly imported
	"os": true, "sys": true, "io": true, "re": true, "json": true,
	"base64": true, "hashlib": true, "hmac": true, "html": true,
	"urllib": true, "subprocess": true, "shutil": true, "time": true,
	"datetime": true, "math": true, "random": true, "secrets": true,
	"struct": true, "string": true, "collections": true, "itertools": true,
	"functools": true, "operator": true, "copy": true, "pathlib": true,
	"configparser": true, "tempfile": true, "logging": true, "uuid": true,
	"pickle": true, "yaml": true, "xml": true, "csv": true, "ast": true,
	"socket": true, "ssl": true, "ipaddress": true, "binascii": true,
	"glob": true, "fnmatch": true, "platform": true, "getpass": true,
	"argparse": true, "typing": true, "dataclasses": true, "enum": true,
	"contextlib": true, "warnings": true, "traceback": true, "inspect": true,
	"helpers": true, "utils": true,
	// Common method/attr names used in `obj.method()` chains
	"encode": true, "decode": true, "split": true, "join": true, "strip": true,
	"lstrip": true, "rstrip": true, "upper": true, "lower": true, "replace": true,
	"startswith": true, "endswith": true, "find": true, "index": true, "count": true,
	"format": true, "rjust": true, "ljust": true, "zfill": true, "title": true,
	"b64encode": true, "b64decode": true, "urlsafe_b64encode": true, "urlsafe_b64decode": true,
	"getlist": true, "get": true,
	"append": true, "pop": true, "extend": true, "insert": true, "remove": true,
	"loads": true, "dumps": true, "load": true, "dump": true,
	"escape_for_html": true, "escape": true, "markupsafe": true,
	// Framework / request markers (skip so we surface the underlying var)
	"request": true, "flask": true, "make_response": true, "render_template": true,
	"redirect": true, "url_for": true, "Response": true, "abort": true,
	"jsonify": true, "send_from_directory": true,
	// Keywords / qualifiers
	"if": true, "else": true, "elif": true, "for": true, "in": true, "and": true,
	"or": true, "not": true, "is": true, "return": true, "yield": true,
	"await": true, "async": true, "with": true, "as": true, "lambda": true,
	"def": true, "class": true, "try": true, "except": true, "finally": true,
	"raise": true, "from": true, "import": true, "global": true, "nonlocal": true,
	// utf-8 etc. encoding constants are not identifiers, but keep utf8 forms
	"utf": true, "ascii": true, "latin1": true,
}
