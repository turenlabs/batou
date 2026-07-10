package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Qt sanitizer tests
//
// Each category has a negative control (tainted value flows to the sink with
// NO sanitizer → flow expected) and a positive test (the Qt sanitizer wraps
// the value → flow neutralized). Source is getenv() (an external/user input),
// matching the convention in the other C++ sanitizer test files.
// =========================================================================

// ── QString::toHtmlEscaped() → SnkHTMLOutput (CWE-79) ────────────────────

func TestCPP_Qt_ToHtmlEscaped_Unsanitized(t *testing.T) {
	code := `
#include <crow.h>
#include <QString>
#include <cstdlib>

void render(crow::response &res) {
    char *userInput = getenv("USER_INPUT");
    QString tainted = QString::fromUtf8(userInput);
    res.write(tainted);
}
`
	flows := Analyze(code, "/app/render_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected HTML output flow for getenv -> res.write without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Qt_ToHtmlEscaped_Sanitized(t *testing.T) {
	code := `
#include <crow.h>
#include <QString>
#include <cstdlib>

void render(crow::response &res) {
    char *userInput = getenv("USER_INPUT");
    QString tainted = QString::fromUtf8(userInput);
    QString safe = tainted.toHtmlEscaped();
    res.write(safe);
}
`
	flows := Analyze(code, "/app/render_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Errorf("expected NO HTML flow when input is sanitized via QString::toHtmlEscaped() (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

// ── QDir::cleanPath() → SnkFileWrite / SnkFileRead (CWE-22) ───────────────

func TestCPP_Qt_CleanPath_Unsanitized(t *testing.T) {
	code := `
#include <cstdio>
#include <QString>
#include <cstdlib>

void saveFile() {
    char *userPath = getenv("FILE_PATH");
    QString tainted = QString::fromUtf8(userPath);
    FILE *f = fopen(tainted, "w");
    fputs("data", f);
}
`
	flows := Analyze(code, "/app/save_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for getenv -> fopen without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// QDir::cleanPath() alone is NOT a sanitizer: it only normalizes separators
// and collapses redundant "." / ".." segments lexically —
// cleanPath("../../etc/passwd") is still "../../etc/passwd"; it does not
// reject escapes. The taint flow must survive. (This test previously
// asserted the opposite, which was unsound — see the filepath.Clean note in
// go_sanitizers.go and the os.path.normpath note in python_sanitizers.go;
// only canonicalize + containment is a defence.)
func TestCPP_Qt_CleanPath_NotASanitizer(t *testing.T) {
	code := `
#include <cstdio>
#include <QDir>
#include <QString>
#include <cstdlib>

void saveFile() {
    char *userPath = getenv("FILE_PATH");
    QString tainted = QString::fromUtf8(userPath);
    QString safe = QDir::cleanPath(tainted);
    FILE *f = fopen(safe, "w");
    fputs("data", f);
}
`
	flows := Analyze(code, "/app/save_safe.cpp", rules.LangCPP)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite || f.Sink.Category == taint.SnkFileRead {
			found = true
		}
	}
	if !found {
		t.Error("QDir::cleanPath() alone must NOT neutralize file taint — expected the traversal flow to still fire")
	}
}

// ── QUrl::toPercentEncoding() → SnkHeader (CWE-113) ───────────────────────

func TestCPP_Qt_ToPercentEncoding_Unsanitized(t *testing.T) {
	code := `
#include <crow.h>
#include <QString>
#include <cstdlib>

void setTag(crow::response &res) {
    char *userInput = getenv("SESSION_TAG");
    QString tainted = QString::fromUtf8(userInput);
    res.set_header("X-Session", tainted);
}
`
	flows := Analyze(code, "/app/header_unsafe.cpp", rules.LangCPP)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("expected header flow for getenv -> res.set_header without sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestCPP_Qt_ToPercentEncoding_Sanitized(t *testing.T) {
	code := `
#include <crow.h>
#include <QUrl>
#include <QString>
#include <cstdlib>

void setTag(crow::response &res) {
    char *userInput = getenv("SESSION_TAG");
    QString tainted = QString::fromUtf8(userInput);
    QByteArray safe = QUrl::toPercentEncoding(tainted);
    res.set_header("X-Session", safe);
}
`
	flows := Analyze(code, "/app/header_safe.cpp", rules.LangCPP)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Errorf("expected NO header flow when value is sanitized via QUrl::toPercentEncoding() (got %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}
