package tsflow

import (
	"regexp"

	"github.com/turenlabs/batou-rules/rules"
)

// A CLI entrypoint is a script whose whole purpose is to accept arguments
// from the user. When such a script passes an argparse / sys.argv value
// into a file I/O sink, it isn't "path traversal" — the path IS the
// interface. We demote the confidence of these flows so they surface as
// hints rather than critical blocks.

// pyCliMainRe matches a Python top-level `if __name__ == "__main__":` block,
// the canonical Python CLI entrypoint marker. Single/double quotes, arbitrary
// whitespace.
var pyCliMainRe = regexp.MustCompile(`(?m)^\s*if\s+__name__\s*==\s*['"]__main__['"]\s*:`)

// pyShebangRe matches a shebang line that invokes Python.
var pyShebangRe = regexp.MustCompile(`\A#![^\n]*python`)

// pyWebFrameworkRe matches imports of common Python web frameworks. A file
// that handles web traffic is NOT a CLI script even if it happens to have an
// `if __name__ == "__main__":` block (e.g. for `app.run()` in dev mode) —
// and the same user-input → file-sink pattern is a real path-traversal
// vulnerability there.
var pyWebFrameworkRe = regexp.MustCompile(
	`(?m)^\s*(?:from|import)\s+(?:flask|django|fastapi|bottle|pyramid|tornado|aiohttp|starlette|sanic|falcon|cherrypy|quart|litestar)\b`)

// isCLIScript reports whether the file looks like a CLI entrypoint for its
// language. Currently only Python has a clear marker — for other languages
// we conservatively return false (no demotion).
func isCLIScript(content string, lang rules.Language) bool {
	switch lang {
	case rules.LangPython:
		if !pyCliMainRe.MatchString(content) && !pyShebangRe.MatchString(content) {
			return false
		}
		// A file that imports a web framework isn't a "pure CLI" even if it
		// has an __main__ guard (that's a common idiom for dev-server boot).
		// Leave those findings at full confidence — a request-handler writing
		// user-controlled paths is a real traversal vulnerability.
		if pyWebFrameworkRe.MatchString(content) {
			return false
		}
		return true
	}
	return false
}
