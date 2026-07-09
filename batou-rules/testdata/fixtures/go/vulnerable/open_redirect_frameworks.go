package vulnerable

import (
	"io"
	"net/http"
	"os"

	"github.com/gobuffalo/buffalo"
	"github.com/kataras/iris/v12"
	"github.com/valyala/fasthttp"
)

// VULN: Open redirect in framework-specific redirect sinks. The destination
// is read from user-controlled input (env var, file, etc.) and passed
// without validation to each framework's Redirect method.

func FasthttpRedirectBytes(ctx *fasthttp.RequestCtx) {
	// batou:ignore BATOU-AST-004 -- deliberately-vulnerable fixture for taint test
	f, _ := os.Open("/tmp/target.txt")
	b, _ := io.ReadAll(f)
	ctx.RedirectBytes(b, fasthttp.StatusFound)
}

func IrisRedirect(ctx iris.Context) {
	target := os.Getenv("REDIRECT_TARGET")
	ctx.Redirect(target, http.StatusFound)
}

func BuffaloRedirect(c buffalo.Context) error {
	target := os.Getenv("REDIRECT_TARGET")
	return c.Redirect(http.StatusFound, target)
}
