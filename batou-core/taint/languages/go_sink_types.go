package languages

import "github.com/turenlabs/batou-core/taint"

// SinkTypeInfo describes a sink-bearing Go type: the category of sink its
// dangerous methods represent, and the method names that consume tainted data
// when called on values of this type.
type SinkTypeInfo struct {
	Category         taint.SinkCategory
	DangerousMethods []string
}

// KnownGoSinkTypes flags parameter types whose methods are dangerous enough
// that receiving one positions the function as a sink host. Used to hint
// that passing tainted data through such a parameter is risky even when the
// specific sink-method call lives in a caller.
//
// Keys use the default alias of the import path. See KnownGoSourceTypes
// for canonicalisation rules.
var KnownGoSinkTypes = map[string]SinkTypeInfo{
	"*sql.DB":   {Category: taint.SnkSQLQuery, DangerousMethods: []string{"Query", "Exec", "QueryRow", "QueryContext", "ExecContext"}},
	"*sql.Tx":   {Category: taint.SnkSQLQuery, DangerousMethods: []string{"Query", "Exec", "QueryRow", "QueryContext", "ExecContext"}},
	"*sqlx.DB":  {Category: taint.SnkSQLQuery, DangerousMethods: []string{"Queryx", "Execx", "Select", "Get", "Query", "Exec"}},
	"*sqlx.Tx":  {Category: taint.SnkSQLQuery, DangerousMethods: []string{"Queryx", "Execx", "Select", "Get", "Query", "Exec"}},
	"*exec.Cmd": {Category: taint.SnkCommand, DangerousMethods: []string{"Run", "Start", "Output", "CombinedOutput"}},
	"*os.File":  {Category: taint.SnkFileWrite, DangerousMethods: []string{"Write", "WriteString", "WriteAt"}},
	// Typed-string escape hatches for html/template.
	"template.HTML":      {Category: taint.SnkHTMLOutput, DangerousMethods: nil},
	"template.JS":        {Category: taint.SnkHTMLOutput, DangerousMethods: nil},
	"template.URL":       {Category: taint.SnkRedirect, DangerousMethods: nil},
	"*template.Template": {Category: taint.SnkTemplate, DangerousMethods: []string{"Execute", "ExecuteTemplate"}},
	"*log.Logger":        {Category: taint.SnkLog, DangerousMethods: []string{"Printf", "Println", "Print"}},
}

// LookupGoSinkType returns the sink info for a canonical Go type, or
// (zero, false) if the type is not a known sink-bearing type.
func LookupGoSinkType(canonicalType string) (SinkTypeInfo, bool) {
	info, ok := KnownGoSinkTypes[canonicalType]
	return info, ok
}
