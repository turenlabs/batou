package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C path-helper + libsoup URI-encoding sanitizer tests.
//
// Return-value sanitizers matching the tsflow args[0]-tainted model
// (tainted string is the FIRST argument, sanitized result is the function's
// return value assigned to a fresh LHS variable):
//
//   g_path_get_basename    — GLib basename extraction (file paths)
//   apr_filepath_name_get  — Apache Portable Runtime basename (file paths)
//   soup_uri_encode        — libsoup URI percent-encoding (URL/redirect)
//
// xmlCanonicPath and g_canonicalize_filename were REMOVED from the sanitizer
// catalog: both are canonicalize-only and do not reject escapes
// (xmlCanonicPath leaves "../" intact; g_canonicalize_filename resolves ".."
// against the base dir and happily returns a path outside it). See the
// realpath note in c_sanitizers.go, the filepath.Clean note in
// go_sanitizers.go, and the os.path.normpath/realpath note in
// python_sanitizers.go — only canonicalize + containment is a defence. Their
// tests below now assert the taint flow SURVIVES.
//
// Each sanitizer has a negative-control test (sink fires without sanitizer)
// plus a positive sanitization test (sink does not fire with sanitizer).
// =========================================================================

// --- xmlCanonicPath: canonicalize-only, NOT a sanitizer ------------------

func TestC_XmlCanonicPath_NegativeControl_FileWriteFires(t *testing.T) {
	code := `
#include <stdio.h>
#include <stdlib.h>

void write_log_unsafe(void) {
    char *user_path = getenv("LOG_PATH");
    FILE *fp = fopen(user_path, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/write_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("negative control: tainted user_path flowing into fopen should produce SnkFileWrite flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// xmlCanonicPath() alone is NOT a sanitizer — it percent-escapes non-URI
// characters but "../" survives untouched, so traversal still reaches the
// sink. The taint flow must survive. (Previously asserted the opposite,
// which was unsound — see the file header comment.)
func TestC_XmlCanonicPath_NotASanitizer(t *testing.T) {
	code := `
#include <libxml/uri.h>
#include <stdio.h>
#include <stdlib.h>

void write_log_canonical(void) {
    char *user_path = getenv("LOG_PATH");
    xmlChar *safe = xmlCanonicPath((const xmlChar *)user_path);
    FILE *fp = fopen((const char *)safe, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/write_safe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("xmlCanonicPath() alone must NOT neutralize FileWrite taint — expected the traversal flow to still fire")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- g_canonicalize_filename: canonicalize-only, NOT a sanitizer ---------

func TestC_GCanonicalizeFilename_NegativeControl_FileWriteFires(t *testing.T) {
	code := `
#include <stdio.h>
#include <stdlib.h>

void open_user_file_unsafe(void) {
    char *user_path = getenv("UPLOAD_PATH");
    FILE *fp = fopen(user_path, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/upload_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("negative control: tainted user_path flowing into fopen should produce SnkFileWrite flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// g_canonicalize_filename() alone is NOT a sanitizer — it resolves ".."
// AGAINST the base dir and happily returns a path outside it
// (g_canonicalize_filename("../../etc/passwd", "/var/uploads") ==
// "/etc/passwd"). The taint flow must survive. (Previously asserted the
// opposite, which was unsound — see the file header comment.)
func TestC_GCanonicalizeFilename_NotASanitizer(t *testing.T) {
	code := `
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

void open_user_file_canonical(void) {
    char *user_path = getenv("UPLOAD_PATH");
    gchar *safe = g_canonicalize_filename(user_path, "/var/uploads");
    FILE *fp = fopen(safe, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/upload_safe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("g_canonicalize_filename() alone must NOT neutralize FileWrite taint — expected the traversal flow to still fire")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.glib.path_get_basename (SnkFileRead, SnkFileWrite) ---------------

func TestC_GPathGetBasename_NegativeControl_FileWriteFires(t *testing.T) {
	code := `
#include <stdio.h>
#include <stdlib.h>

void save_attachment_unsafe(void) {
    char *user_name = getenv("FILENAME");
    FILE *fp = fopen(user_name, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/attach_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("negative control: tainted user_name flowing into fopen should produce SnkFileWrite flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_GPathGetBasename_Sanitizes_FileWrite(t *testing.T) {
	code := `
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

void save_attachment_safe(void) {
    char *user_name = getenv("FILENAME");
    gchar *base = g_path_get_basename(user_name);
    FILE *fp = fopen(base, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/attach_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("g_path_get_basename() should neutralize path-traversal — no SnkFileWrite flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.apr.filepath_name_get (SnkFileRead, SnkFileWrite) ----------------

func TestC_AprFilepathNameGet_NegativeControl_FileWriteFires(t *testing.T) {
	code := `
#include <stdio.h>
#include <stdlib.h>

void store_blob_unsafe(void) {
    char *user_path = getenv("BLOB_PATH");
    FILE *fp = fopen(user_path, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/blob_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("negative control: tainted user_path flowing into fopen should produce SnkFileWrite flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_AprFilepathNameGet_Sanitizes_FileWrite(t *testing.T) {
	code := `
#include <apr_lib.h>
#include <stdio.h>
#include <stdlib.h>

void store_blob_safe(void) {
    char *user_path = getenv("BLOB_PATH");
    const char *base = apr_filepath_name_get(user_path);
    FILE *fp = fopen(base, "w");
    (void)fp;
}
`
	flows := Analyze(code, "/app/blob_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("apr_filepath_name_get() should neutralize path-traversal — no SnkFileWrite flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- c.soup.uri_encode (SnkURLFetch, SnkRedirect, SnkHeader) ------------

func TestC_SoupUriEncode_NegativeControl_URLFetchFires(t *testing.T) {
	code := `
#include <netdb.h>
#include <stdlib.h>

void resolve_unsafe(void) {
    char *user_host = getenv("HOST");
    struct addrinfo *result;
    getaddrinfo(user_host, NULL, NULL, &result);
}
`
	flows := Analyze(code, "/app/resolve_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("negative control: tainted user_host flowing into getaddrinfo should produce SnkURLFetch flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SoupUriEncode_Sanitizes_URLFetch(t *testing.T) {
	code := `
#include <libsoup/soup.h>
#include <netdb.h>
#include <stdlib.h>

void resolve_safe(void) {
    char *user_host = getenv("HOST");
    char *escaped = soup_uri_encode(user_host, NULL);
    struct addrinfo *result;
    getaddrinfo(escaped, NULL, NULL, &result);
}
`
	flows := Analyze(code, "/app/resolve_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("soup_uri_encode() should neutralize URL fetch — no SnkURLFetch flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SoupUriEncode_NegativeControl_RedirectFires(t *testing.T) {
	code := `
#include <civetweb.h>
#include <stdlib.h>

void redirect_unsafe(struct mg_connection *conn) {
    char *user_target = getenv("TARGET");
    mg_send_http_redirect(conn, user_target, 302);
}
`
	flows := Analyze(code, "/app/redir_unsafe.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("negative control: tainted user_target flowing into mg_send_http_redirect should produce SnkRedirect flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SoupUriEncode_Sanitizes_Redirect(t *testing.T) {
	code := `
#include <libsoup/soup.h>
#include <civetweb.h>
#include <stdlib.h>

void redirect_safe(struct mg_connection *conn) {
    char *user_target = getenv("TARGET");
    char *escaped = soup_uri_encode(user_target, "/");
    mg_send_http_redirect(conn, escaped, 302);
}
`
	flows := Analyze(code, "/app/redir_safe.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("soup_uri_encode() should neutralize redirect — no SnkRedirect flow expected")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
