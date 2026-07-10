package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// PR-BB: framework-aware Go sources. These tests assert that user input
// extracted via Gin / Echo / Fiber / Chi / mux / r.PathValue helpers is
// recognized as a taint source and flows to a SQL sink. The existing astflow
// engine does not handle inline source-to-sink (db.Exec(c.Param("id"))) for
// any source, so each fixture binds the source to a variable first — same
// shape as the existing TestAnalyzeGo_GinFramework test.

func TestAnalyzeGo_PRBB_GinParam(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

func H(c *gin.Context) {
	id := c.Param("id")
	db.Exec(id)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Gin c.Param -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_GinDefaultPostForm(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

func H(c *gin.Context) {
	v := c.DefaultPostForm("k", "")
	db.Exec(v)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Gin c.DefaultPostForm -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_GinShouldBindXML(t *testing.T) {
	t.Skip("Known astflow limitation: pointer-arg taint propagation through bind methods. " +
		"c.ShouldBindXML(&in) mutates *in via the request body; astflow tracks taint by " +
		"name and can't model SSA-level pointee mutation. PR-DD adds this in the ssaflow " +
		"engine — see ssaflow/pointer_arg_test.go TestAnalyzeGo_PointerArg_GinShouldBindXML " +
		"for the equivalent SSA-tier coverage (env-gated under BATOU_SSAFLOW=1).")
	code := `package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
)

type In struct{ Name string }

func H(c *gin.Context) {
	var in In
	_ = c.ShouldBindXML(&in)
	db.Exec(in.Name)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Gin c.ShouldBindXML -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_EchoQueryParam(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/labstack/echo/v4"
)

func H(c echo.Context) error {
	q := c.QueryParam("q")
	db.Exec(q)
	return nil
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Echo c.QueryParam -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_EchoFormValues(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/labstack/echo/v4"
)

func H(c echo.Context) error {
	vs, _ := c.FormValues()
	for _, v := range vs {
		db.Exec(v[0])
	}
	return nil
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Echo c.FormValues -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_FiberQuery(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/gofiber/fiber/v2"
)

func H(c *fiber.Ctx) error {
	q := c.Query("q")
	db.Exec(q)
	return nil
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Fiber c.Query -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_FiberGet(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/gofiber/fiber/v2"
)

func H(c *fiber.Ctx) error {
	h := c.Get("X-Forwarded-User")
	db.Exec(h)
	return nil
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Fiber c.Get(header) -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_FiberQueryParser(t *testing.T) {
	t.Skip("Known astflow limitation: pointer-arg taint propagation through bind methods. " +
		"c.QueryParser(&in) mutates *in via the request query string; astflow tracks taint " +
		"by name and can't model SSA-level pointee mutation. PR-DD adds this in the ssaflow " +
		"engine — see ssaflow/pointer_arg_test.go TestAnalyzeGo_PointerArg_FiberQueryParser " +
		"for the equivalent SSA-tier coverage (env-gated under BATOU_SSAFLOW=1).")
	code := `package main

import (
	"database/sql"

	"github.com/gofiber/fiber/v2"
)

type In struct{ Name string }

func H(c *fiber.Ctx) error {
	var in In
	_ = c.QueryParser(&in)
	db.Exec(in.Name)
	return nil
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Fiber c.QueryParser -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_ChiURLParam(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func H(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	db.Exec(id)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for chi.URLParam -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_ChiURLParamFromCtx(t *testing.T) {
	code := `package main

import (
	"context"
	"database/sql"

	"github.com/go-chi/chi/v5"
)

func H(ctx context.Context) {
	id := chi.URLParamFromCtx(ctx, "id")
	db.Exec(id)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for chi.URLParamFromCtx -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_GorillaMuxVars(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

func H(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	db.Exec(v["id"])
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for mux.Vars -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_PRBB_HTTPPathValue(t *testing.T) {
	code := `package main

import (
	"database/sql"
	"net/http"
)

func H(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	db.Exec(name)
}

var db *sql.DB
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for r.PathValue -> db.Exec")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.ID, f.Sink.Category)
		}
	}
}
