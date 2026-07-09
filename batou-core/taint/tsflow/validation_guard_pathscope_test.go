package tsflow

// Tests for CATEGORY-SCOPED clearing in the generic validation-guard path.
//
// The generic allowlist/validation fallback in processIfBranchAware used to
// delete the validated variable from the taint map WHOLESALE — so a
// path-containment check like `if (id.contains("..")) return;` silenced SQL
// injection on the same variable (a path check says nothing about SQL/command
// /XSS safety). Python already scoped this exact shape (`".." in x`) to the
// path sink categories via inferPythonPathGuard; these tests pin the same
// behaviour for the languages that go through detectValidationGuard — Java
// (receiver-method shape) and PHP (free-function strpos/str_contains shape),
// the two languages where the wholesale-clear FN empirically reproduced.
//
// Coverage:
//   - dot-dot containment guard before an INJECTION sink → flow FIRES (was FN)
//   - dot-dot containment guard before a FILE sink → still SILENT (TN kept)
//   - dot-dot containment guard before a URL sink → still SILENT (status quo:
//     the wholesale clear suppressed these, and the scoped set keeps
//     SnkURLFetch/SnkRedirect cleared so no FP flips)
//   - non-path validation shape (quote guard, filter_var) → wholesale
//     clearing kept (status quo)
//   - URL-shaped literal (contains "://") → wholesale clearing kept

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// --- Java (the reproduced FN: receiver-method containment shape) ---

func TestVG_Java_DotDotGuard_SQLiStillFires(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        if (id.contains("..")) {
            return;
        }
        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if !bgHasCat(flows, taint.SnkSQLQuery) {
		t.Error("Java: a '..' path-containment guard must NOT silence SQL injection on the same variable")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestVG_Java_StartsWithDotDotGuard_SQLiStillFires(t *testing.T) {
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        if (id.startsWith("../")) {
            return;
        }
        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
}
`
	if !bgHasCat(Analyze(code, "/app/Handler.java", rules.LangJava), taint.SnkSQLQuery) {
		t.Error("Java: a startsWith(\"../\") path guard must NOT silence SQL injection")
	}
}

func TestVG_Java_DotDotGuard_FileSinkStillSilent(t *testing.T) {
	code := `
import javax.servlet.http.*;
import java.io.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        if (id.contains("..")) {
            return;
        }
        FileInputStream fis = new FileInputStream("/data/" + id);
    }
}
`
	flows := Analyze(code, "/app/Handler.java", rules.LangJava)
	if bgHasCat(flows, taint.SnkFileRead) || bgHasCat(flows, taint.SnkFileWrite) || bgHasCat(flows, taint.SnkUpload) {
		t.Error("Java: a '..' guard + early return must still suppress the path-traversal flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestVG_Java_QuoteGuard_WholesaleStatusQuo(t *testing.T) {
	// A non-path validation shape (quote containment before a SQL sink) must
	// keep the existing wholesale-clear behaviour: unrecognised validation
	// shapes stay status quo so existing FP suppression does not flip.
	code := `
import javax.servlet.http.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = request.getParameter("id");
        if (id.contains("'")) {
            return;
        }
        stmt.executeQuery("SELECT * FROM t WHERE id=" + id);
    }
}
`
	if bgHasCat(Analyze(code, "/app/Handler.java", rules.LangJava), taint.SnkSQLQuery) {
		t.Error("Java: an unrecognised validation shape (quote guard) must keep clearing taint wholesale")
	}
}

func TestVG_Java_URLPrefixGuard_WholesaleStatusQuo(t *testing.T) {
	// A literal containing "://" is a URL-prefix guard, not a filesystem path
	// check — keep the wholesale behaviour so SSRF/redirect FP suppression
	// does not flip.
	code := `
import javax.servlet.http.*;
import java.net.*;

public class Handler extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String target = request.getParameter("target");
        if (!target.startsWith("https://trusted.example.com/")) {
            return;
        }
        URL url = new URL(target);
        url.openConnection();
    }
}
`
	if bgHasCat(Analyze(code, "/app/Handler.java", rules.LangJava), taint.SnkURLFetch) {
		t.Error("Java: a https:// prefix guard must keep clearing taint wholesale (no new SSRF FP)")
	}
}

// --- PHP (the reproduced FN in a dynamic language: strpos/str_contains) ---

func TestVG_PHP_StrposDotDotGuard_SQLiStillFires(t *testing.T) {
	code := `<?php
$p = $_GET['p'];
if (strpos($p, '..') !== false) { die("bad"); }
mysqli_query($conn, "SELECT * FROM t WHERE x = '$p'");
`
	flows := Analyze(code, "/var/www/x.php", rules.LangPHP)
	if !bgHasCat(flows, taint.SnkSQLQuery) {
		t.Error("PHP: a strpos($p, '..') path guard must NOT silence SQL injection on the same variable")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestVG_PHP_StrContainsDotDotGuard_SQLiStillFires(t *testing.T) {
	code := `<?php
$p = $_GET['p'];
if (str_contains($p, '..')) { die("bad"); }
mysqli_query($conn, "SELECT * FROM t WHERE x = '$p'");
`
	if !bgHasCat(Analyze(code, "/var/www/x.php", rules.LangPHP), taint.SnkSQLQuery) {
		t.Error("PHP: a str_contains($p, '..') path guard must NOT silence SQL injection")
	}
}

func TestVG_PHP_StrposDotDotGuard_FileSinkStillSilent(t *testing.T) {
	code := `<?php
$p = $_GET['p'];
if (strpos($p, '..') !== false) { die("bad"); }
include('/var/templates/' . $p);
`
	flows := Analyze(code, "/var/www/x.php", rules.LangPHP)
	if bgHasCat(flows, taint.SnkFileRead) || bgHasCat(flows, taint.SnkFileWrite) || bgHasCat(flows, taint.SnkUpload) {
		t.Error("PHP: a strpos('..') guard + die() must still suppress the path-traversal/inclusion flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (sink=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestVG_PHP_StrposDotDotGuard_URLFetchStillSilent(t *testing.T) {
	// The historical wholesale clear also suppressed url_fetch flows after a
	// '..' guard (host-fixed proxy idiom). The scoped category set keeps
	// SnkURLFetch/SnkRedirect cleared so this FP suppression does not flip.
	code := `<?php
$e = $_GET['endpoint'];
if (strpos($e, '..') !== false) { die("Invalid"); }
$url = 'https://api.example.com' . $e;
$response = file_get_contents($url);
`
	if bgHasCat(Analyze(code, "/var/www/proxy.php", rules.LangPHP), taint.SnkURLFetch) {
		t.Error("PHP: a strpos('..') guard must keep suppressing the url_fetch flow (status quo)")
	}
}

func TestVG_PHP_FilterVarGuard_WholesaleStatusQuo(t *testing.T) {
	// filter_var is a guard builtin we cannot classify — it must keep the
	// wholesale clear (status quo) so the SQL flow stays suppressed.
	code := `<?php
$p = $_GET['p'];
if (filter_var($p, FILTER_VALIDATE_EMAIL) === false) { die("bad"); }
mysqli_query($conn, "SELECT * FROM t WHERE x = '$p'");
`
	if bgHasCat(Analyze(code, "/var/www/x.php", rules.LangPHP), taint.SnkSQLQuery) {
		t.Error("PHP: an unclassifiable validator (filter_var) must keep clearing taint wholesale")
	}
}
