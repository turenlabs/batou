package astflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Tests for Iris (kataras/iris/v12) request input sources.
// All handlers use the idiomatic `ctx iris.Context` parameter so the astflow
// TypeEnv resolves "ctx" to "iris.Context" via the function declaration.

func TestAnalyzeGo_IrisURLParam_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/kataras/iris/v12"
)

var db *sql.DB

func handler(ctx iris.Context) {
	name := ctx.URLParam("name")
	db.Query("SELECT * FROM users WHERE name = '" + name + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Iris URLParam -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisPostValue_CmdInj(t *testing.T) {
	code := `package main

import (
	"os/exec"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	cmd := ctx.PostValue("cmd")
	exec.Command("sh", "-c", cmd).Run()
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for Iris PostValue -> exec.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisFormValue_FileRead(t *testing.T) {
	code := `package main

import (
	"os"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	name := ctx.FormValue("filename")
	os.ReadFile("/var/data/" + name)
}
`
	// Note: the existing catalog categorizes os.ReadFile as SnkFileWrite
	// (a pre-existing convention in go_sinks.go); the test asserts the
	// flow exists, regardless of how this codebase labels file ops.
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-op flow for Iris FormValue -> os.ReadFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisGetHeader_SSRF(t *testing.T) {
	code := `package main

import (
	"net/http"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	target := ctx.GetHeader("X-Forward-To")
	http.Get(target)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for Iris GetHeader -> http.Get")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisGetCookie_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/kataras/iris/v12"
)

var db *sql.DB

func handler(ctx iris.Context) {
	tok := ctx.GetCookie("session")
	db.Query("SELECT * FROM sessions WHERE token = '" + tok + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for Iris GetCookie -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisPath_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	p := ctx.Path()
	log.Printf("request: %s", p)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for Iris Path -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisRemoteAddr_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	ip := ctx.RemoteAddr()
	log.Printf("from %s", ip)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for Iris RemoteAddr -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisHost_OpenRedirect(t *testing.T) {
	code := `package main

import (
	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	h := ctx.Host()
	ctx.Redirect("https://"+h+"/login", 302)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for Iris Host -> ctx.Redirect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisUserAgent_LogInjection(t *testing.T) {
	code := `package main

import (
	"log"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	ua := ctx.UserAgent()
	log.Printf("ua=%s", ua)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for Iris UserAgent -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisGetBody_SQLi(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/kataras/iris/v12"
)

var db *sql.DB

func handler(ctx iris.Context) {
	body, _ := ctx.GetBody()
	db.Query("SELECT * FROM logs WHERE raw = '" + string(body) + "'")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL flow for Iris GetBody -> db.Query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisFormFile_PathTraversal(t *testing.T) {
	code := `package main

import (
	"os"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	_, hdr, _ := ctx.FormFile("upload")
	os.WriteFile("/var/uploads/"+hdr.Filename, []byte{}, 0644)
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file-write flow for Iris FormFile -> os.WriteFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestAnalyzeGo_IrisURLParams_LogInjection(t *testing.T) {
	code := `package main

import (
	"fmt"
	"log"

	"github.com/kataras/iris/v12"
)

func handler(ctx iris.Context) {
	all := ctx.URLParams()
	log.Printf("params: %s", fmt.Sprint(all))
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log-injection flow for Iris URLParams -> log.Printf")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative regression test: a constant string passed to db.Query must NOT
// produce a flow even though the same handler uses iris.Context for other
// params. Guards against over-broad ObjectType matching.
func TestAnalyzeGo_IrisConstant_NoFlow(t *testing.T) {
	code := `package main

import (
	"database/sql"

	"github.com/kataras/iris/v12"
)

var db *sql.DB

func handler(ctx iris.Context) {
	_ = ctx.URLParam("debug")
	db.Query("SELECT 1")
}
`
	flows := AnalyzeGo(code, "/app/handler.go")
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did NOT expect SQL flow for constant query — Iris source must not over-broaden")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
