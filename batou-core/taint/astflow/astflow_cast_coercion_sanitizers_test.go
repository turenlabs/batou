package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// spf13/cast type-coercion sanitisers.
//
// github.com/spf13/cast is one of the most widely used Go coercion
// libraries (a transitive dependency of Viper/Cobra). Its To<Type> helpers
// coerce an `any` value to a strongly-typed scalar, returning the zero
// value on failure. Coercing a tainted string to int/uint/float/bool drops
// any embedded string-injection payload — the same neutralisation contract
// already recognised for the strconv.Parse* family.
//
// These tests assert:
//   1. A positive control (no coercion) still flags SQL injection, so the
//      fixture wiring genuinely detects the flow.
//   2. cast.ToInt / ToUint / ToFloat64 / ToBool (and the error-returning
//      ToIntE form) neutralise the flow when the COERCED value reaches the
//      sink.
//   3. The arg[0]-only contract holds: if the coerced result is discarded
//      and the ORIGINAL tainted string still reaches the sink, the flow is
//      (correctly) still reported — i.e. the sanitiser does not over-suppress.
// =========================================================================

// TestCastSanitizer_NoCoercion_StillFlags is the positive control: without
// any coercion the tainted form value reaches db.Query and SQL injection is
// reported.
func TestCastSanitizer_NoCoercion_StillFlags(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id")
	db.Query("SELECT * FROM users WHERE id = " + raw)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("positive control failed: expected SQL injection flow when the raw form value is concatenated with no coercion")
	}
}

// TestCastSanitizer_ToInt_Sanitized asserts cast.ToInt coerces the tainted
// value to an int, neutralising SQL injection on the coerced value.
func TestCastSanitizer_ToInt_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id")
	id := cast.ToInt(raw)
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when cast.ToInt coerces the input to an integer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestCastSanitizer_ToIntE_Sanitized exercises the error-returning ToIntE
// form, which is assigned as a two-value (value, err) tuple.
func TestCastSanitizer_ToIntE_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id")
	id, err := cast.ToIntE(raw)
	if err != nil {
		return
	}
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when cast.ToIntE coerces the input to an integer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestCastSanitizer_ToUint_Sanitized asserts cast.ToUint neutralises the flow.
func TestCastSanitizer_ToUint_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id")
	id := cast.ToUint64(raw)
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when cast.ToUint64 coerces the input to an unsigned integer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestCastSanitizer_ToFloat64_Sanitized asserts cast.ToFloat64 neutralises
// the flow.
func TestCastSanitizer_ToFloat64_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("amount")
	amt := cast.ToFloat64(raw)
	db.Query(fmt.Sprintf("SELECT * FROM orders WHERE amount = %f", amt))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when cast.ToFloat64 coerces the input to a float")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestCastSanitizer_ToBool_Sanitized asserts cast.ToBool neutralises the flow.
func TestCastSanitizer_ToBool_Sanitized(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/spf13/cast"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("active")
	active := cast.ToBool(raw)
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE active = %t", active))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected NO SQL injection flow when cast.ToBool coerces the input to a boolean")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (line %d)", f.Source.ID, f.Sink.ID, f.SinkLine)
		}
	}
}

// TestCastSanitizer_ResultDiscarded_OriginalStillFlags asserts the
// arg[0]-only contract: the coerced result is assigned to `id` but the sink
// uses the ORIGINAL tainted `raw` string, so the flow must still be reported.
// This proves the sanitiser does not blanket-suppress every nearby flow.
func TestCastSanitizer_ResultDiscarded_OriginalStillFlags(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"

	"github.com/spf13/cast"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("id")
	id := cast.ToInt(raw)
	_ = id
	db.Query("SELECT * FROM users WHERE id = " + raw)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow when the coerced value is discarded and the original tainted string reaches the sink")
	}
}
