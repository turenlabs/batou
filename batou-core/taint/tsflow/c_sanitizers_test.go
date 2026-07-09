package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// ==========================================================================
// C HTML/XML escaping sanitizer tests
// ==========================================================================

func TestC_XmlEncodeSpecialChars_Sanitizes_XSS(t *testing.T) {
	code := `
#include <libxml/xmlstring.h>
#include <stdio.h>
#include <stdlib.h>

void handle_cgi() {
    char *input = getenv("QUERY_STRING");
    xmlChar *safe = xmlEncodeSpecialChars(NULL, (const xmlChar *)input);
    printf("Content-Type: text/html\r\n\r\n<p>%s</p>", safe);
}
`
	flows := Analyze(code, "/app/cgi_xml.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when output is sanitized via xmlEncodeSpecialChars")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_GMarkupEscape_Sanitizes_XSS(t *testing.T) {
	code := `
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

void render_page() {
    char *input = getenv("QUERY_STRING");
    gchar *safe = g_markup_escape_text(input, -1);
    printf("Content-Type: text/html\r\n\r\n<div>%s</div>", safe);
}
`
	flows := Analyze(code, "/app/cgi_glib.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected NO XSS flow when output is sanitized via g_markup_escape_text")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_XSS_Unsanitized(t *testing.T) {
	code := `
#include "mongoose.h"

void handler(struct mg_connection *c, struct mg_http_message *hm) {
    const char *input = mg_http_get_header(hm, "X-Name");
    mg_http_reply(c, 200, "Content-Type: text/html\r\n", "<p>%s</p>", input);
}
`
	flows := Analyze(code, "/app/cgi_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for mg_http_get_header -> mg_http_reply without sanitization")
	}
}

// ==========================================================================
// C command injection escaping (GLib g_shell_quote)
// ==========================================================================

func TestC_GShellQuote_Sanitizes_Command(t *testing.T) {
	code := `
#include <glib.h>
#include <stdlib.h>

void run_command() {
    char *filename = getenv("FILENAME");
    gchar *quoted = g_shell_quote(filename);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cat %s", quoted);
    system(cmd);
}
`
	flows := Analyze(code, "/app/cmd_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO command injection flow when arg is sanitized via g_shell_quote")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Command_Unsanitized(t *testing.T) {
	code := `
#include <stdlib.h>

void run_command() {
    char *cmd = getenv("CMD");
    system(cmd);
}
`
	flows := Analyze(code, "/app/cmd_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for getenv -> system without sanitization")
	}
}

// ==========================================================================
// C URL/SSRF escaping (GLib g_uri_escape_string)
// ==========================================================================

func TestC_GUriEscape_Sanitizes_SSRF(t *testing.T) {
	code := `
#include <glib.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <stdio.h>

void fetch_url(CURL *curl) {
    char *param = getenv("QUERY_STRING");
    char *escaped = g_uri_escape_string(param, NULL, FALSE);
    char url[1024];
    snprintf(url, sizeof(url), "https://api.example.com/search?q=%s", escaped);
    curl_easy_setopt(curl, CURLOPT_URL, url);
}
`
	flows := Analyze(code, "/app/ssrf_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when URL param is sanitized via g_uri_escape_string")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ==========================================================================
// C PostgreSQL escaping (libpq)
// ==========================================================================

func TestC_PQescapeLiteral_Sanitizes_SQLi(t *testing.T) {
	code := `
#include <libpq-fe.h>
#include <stdlib.h>
#include <stdio.h>

void query_db(PGconn *conn) {
    char *name = getenv("QUERY_STRING");
    char *safe = PQescapeLiteral(conn, name, strlen(name));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE name = %s", safe);
    PQexec(conn, query);
}
`
	flows := Analyze(code, "/app/pg_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when value is sanitized via PQescapeLiteral")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_PQescapeIdentifier_Sanitizes_SQLi(t *testing.T) {
	code := `
#include <libpq-fe.h>
#include <stdlib.h>
#include <stdio.h>

void query_table(PGconn *conn) {
    char *table = getenv("TABLE_NAME");
    char *safe_table = PQescapeIdentifier(conn, table, strlen(table));
    char query[1024];
    snprintf(query, sizeof(query), "SELECT * FROM %s", safe_table);
    PQexec(conn, query);
}
`
	flows := Analyze(code, "/app/pg_ident.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when identifier is sanitized via PQescapeIdentifier")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_PQescapeStringConn_Sanitizes_SQLi(t *testing.T) {
	code := `
#include <libpq-fe.h>
#include <stdlib.h>
#include <stdio.h>

void query_db(PGconn *conn) {
    char *input = getenv("QUERY_STRING");
    char safe[1024];
    int err;
    PQescapeStringConn(conn, safe, input, strlen(input), &err);
    char query[2048];
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE name = '%s'", safe);
    PQexec(conn, query);
}
`
	flows := Analyze(code, "/app/pg_escape.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when value is sanitized via PQescapeStringConn")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_PQexec_Unsanitized(t *testing.T) {
	code := `
#include <libpq-fe.h>
#include <stdlib.h>

void query_db(PGconn *conn) {
    char *query = getenv("QUERY_STRING");
    PQexec(conn, query);
}
`
	flows := Analyze(code, "/app/pg_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getenv -> PQexec without sanitization")
	}
}

// ==========================================================================
// C MySQL parameter binding
// ==========================================================================

func TestC_MysqlStmtBind_Sanitizes_SQLi(t *testing.T) {
	code := `
#include <mysql.h>
#include <stdlib.h>

void query_db(MYSQL *conn) {
    char *input = getenv("QUERY_STRING");
    MYSQL_STMT *stmt = mysql_stmt_prepare(conn, "SELECT * FROM users WHERE name = ?", -1);
    MYSQL_BIND bind;
    bind.buffer = input;
    mysql_stmt_bind_param(stmt, &bind);
}
`
	flows := Analyze(code, "/app/mysql_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Error("expected NO SQL injection flow when using mysql_stmt_bind_param")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ==========================================================================
// C OpenSSL crypto sanitizers
// ==========================================================================

func TestC_HMAC_Sanitizes_Crypto(t *testing.T) {
	code := `
#include <openssl/hmac.h>
#include <stdlib.h>

void verify_token() {
    char *token = getenv("AUTH_TOKEN");
    unsigned char result[32];
    unsigned int len;
    HMAC(EVP_sha256(), "secret", 6, (unsigned char *)token, strlen(token), result, &len);
}
`
	flows := Analyze(code, "/app/hmac_verify.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO crypto flow when using HMAC (secure)")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_EVP_AES_GCM_Sanitizes_Crypto(t *testing.T) {
	code := `
#include <openssl/evp.h>
#include <stdlib.h>

void encrypt_data() {
    char *data = getenv("SENSITIVE_DATA");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
}
`
	flows := Analyze(code, "/app/aes_gcm.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO crypto flow when using EVP_aes_256_gcm (secure)")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_EVP_SHA3_Sanitizes_Crypto(t *testing.T) {
	code := `
#include <openssl/evp.h>
#include <stdlib.h>

void hash_data() {
    char *input = getenv("USER_INPUT");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
}
`
	flows := Analyze(code, "/app/sha3_hash.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected NO crypto flow when using EVP_sha3_256 (secure)")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ==========================================================================
// C libcurl SSRF protocol restriction
// ==========================================================================

func TestC_CurlProtocols_Sanitizes_SSRF(t *testing.T) {
	code := `
#include <curl/curl.h>
#include <stdlib.h>

void fetch_url() {
    char *url = getenv("TARGET_URL");
    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_URL, url);
}
`
	flows := Analyze(code, "/app/curl_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch {
			t.Error("expected NO SSRF flow when CURLOPT_PROTOCOLS restricts schemes")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ==========================================================================
// C path sanitizer extended coverage (SnkFileRead)
// ==========================================================================

func TestC_Basename_Sanitizes_FileWrite(t *testing.T) {
	code := `
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>

void write_file() {
    char *path = getenv("FILE_PATH");
    char *safe = basename(path);
    FILE *f = fopen(safe, "w");
    fputs("data", f);
}
`
	flows := Analyze(code, "/app/write_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Error("expected NO file write traversal flow when path is sanitized via basename")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Basename_Sanitizes_FileRead(t *testing.T) {
	code := `
#include <libgen.h>
#include <stdlib.h>
#include <dirent.h>

void list_dir() {
    char *path = getenv("DIR_PATH");
    char *safe = basename(path);
    DIR *d = opendir(safe);
}
`
	flows := Analyze(code, "/app/dir_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO file read traversal flow when path is sanitized via basename")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Log injection sanitizer tests ---

func TestC_SdJournal_Sanitizes_Log(t *testing.T) {
	code := `
#include <systemd/sd-journal.h>
#include <stdlib.h>

void log_user_action() {
    char *username = getenv("USERNAME");
    sd_journal_send("MESSAGE=User logged in: %s", username,
                    "PRIORITY=%d", 6, NULL);
}
`
	flows := Analyze(code, "/app/journal_log.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when using sd_journal_send (structured logging)")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_GLogStructured_Sanitizes_Log(t *testing.T) {
	code := `
#include <glib.h>
#include <stdlib.h>

void log_request() {
    char *input = getenv("QUERY_STRING");
    g_log_structured("myapp", G_LOG_LEVEL_INFO,
                     "MESSAGE", "Request: %s", input);
}
`
	flows := Analyze(code, "/app/glib_log.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when using g_log_structured")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Log_Unsanitized(t *testing.T) {
	code := `
#include <syslog.h>
#include <stdlib.h>

void log_input() {
    char *msg = getenv("USER_MSG");
    syslog(LOG_INFO, msg);
}
`
	flows := Analyze(code, "/app/log_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow when tainted input is used as syslog format string")
	}
}

// --- Header injection sanitizer tests ---

func TestC_CrlfStrpbrk_Sanitizes_Header(t *testing.T) {
	code := `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void set_cookie() {
    char *value = getenv("COOKIE_VAL");
    if (strpbrk(value, "\r\n") != NULL) {
        return;
    }
    printf("Set-Cookie: session=%s\r\n", value);
}
`
	flows := Analyze(code, "/app/header_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHeader {
			t.Error("expected NO header injection flow when CRLF is checked via strpbrk")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_JsonEncode_Sanitizes_Header(t *testing.T) {
	code := `
#include <json-c/json.h>
#include <stdlib.h>
#include <syslog.h>

void log_json() {
    char *input = getenv("USER_INPUT");
    json_object *jstr = json_object_new_string(input);
    const char *safe = json_object_get_string(jstr);
    syslog(LOG_INFO, "data=%s", safe);
}
`
	flows := Analyze(code, "/app/json_log.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Error("expected NO log injection flow when input is JSON-encoded via json_object_new_string")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Trust boundary sanitizer tests ---

func TestC_Clearenv_Sanitizes_TrustBoundary(t *testing.T) {
	code := `
#include <stdlib.h>

void setup_env() {
    char *val = getenv("USER_PATH");
    clearenv();
    setenv("PATH", "/usr/bin", 1);
}
`
	flows := Analyze(code, "/app/env_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when clearenv resets the environment")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SecureGetenv_Sanitizes_TrustBoundary(t *testing.T) {
	code := `
#define _GNU_SOURCE
#include <stdlib.h>

void use_env() {
    char *val = secure_getenv("CONFIG_DIR");
    setenv("APP_DIR", val, 1);
}
`
	flows := Analyze(code, "/app/env_secure.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Error("expected NO trust boundary flow when using secure_getenv (suid-safe)")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_TrustBoundary_Unsanitized(t *testing.T) {
	code := `
#include <stdlib.h>

void set_path() {
    char *val = getenv("USER_PATH");
    setenv("PATH", val, 1);
}
`
	flows := Analyze(code, "/app/env_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow when tainted input goes directly to setenv")
	}
}

// --- Eval / dynamic loading sanitizer tests ---

func TestC_Pcre2Jit_Sanitizes_Eval(t *testing.T) {
	code := `
#include <pcre2.h>
#include <stdlib.h>

void compile_pattern() {
    char *pattern = getenv("REGEX_PATTERN");
    int errcode;
    PCRE2_SIZE erroffset;
    pcre2_code *re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                    0, &errcode, &erroffset, NULL);
    pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
}
`
	flows := Analyze(code, "/app/regex_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Error("expected NO eval/ReDoS flow when regex uses pcre2_jit_compile (backtrack limits)")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Eval_Unsanitized_Dlopen(t *testing.T) {
	code := `
#include <dlfcn.h>
#include <stdlib.h>

void load_plugin() {
    char *path = getenv("PLUGIN_PATH");
    void *handle = dlopen(path, RTLD_NOW);
}
`
	flows := Analyze(code, "/app/dlopen_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow when tainted path goes directly to dlopen")
	}
}

// ==========================================================================
// C path traversal sanitizer tests (CWE-22)
// ==========================================================================

func TestC_GlibBase64Encode_Sanitizes_Command(t *testing.T) {
	code := `
#include <glib.h>
#include <stdlib.h>

void encode_and_exec() {
    char *input = getenv("USER_DATA");
    gchar *safe = g_base64_encode((guchar *)input, strlen(input));
    system(safe);
    g_free(safe);
}
`
	flows := Analyze(code, "/app/base64_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Error("expected NO command injection flow when data is base64-encoded via g_base64_encode")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mkstemp_Sanitizes_FileWrite(t *testing.T) {
	code := `
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void safe_temp_write() {
    char *data = getenv("USER_DATA");
    char template[] = "/tmp/upload_XXXXXX";
    int fd = mkstemp(template);
    write(fd, data, strlen(data));
}
`
	flows := Analyze(code, "/app/mkstemp_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileWrite {
			t.Error("expected NO file write traversal flow when mkstemp generates safe path")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Mkdtemp_Sanitizes_FileRead(t *testing.T) {
	code := `
#include <stdlib.h>
#include <dirent.h>

void safe_temp_dir() {
    char *input = getenv("USER_INPUT");
    char template[] = "/tmp/work_XXXXXX";
    char *dir = mkdtemp(template);
    DIR *d = opendir(dir);
}
`
	flows := Analyze(code, "/app/mkdtemp_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead {
			t.Error("expected NO file read traversal flow when mkdtemp generates safe path")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_FileRead_Unsanitized_Opendir(t *testing.T) {
	code := `
#include <stdlib.h>
#include <dirent.h>

void unsafe_list() {
    char *path = getenv("DIR_PATH");
    DIR *d = opendir(path);
}
`
	flows := Analyze(code, "/app/opendir_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow when tainted path goes directly to opendir")
	}
}

// ==========================================================================
// C LDAP sanitizer tests (CWE-90)
// ==========================================================================

func TestC_LdapStr2dn_Sanitizes_LDAP(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void search_user() {
    char *dn = getenv("USER_DN");
    LDAPDN parsed;
    int rc = ldap_str2dn(dn, &parsed, LDAP_DN_FORMAT_LDAPV3);
    if (rc == LDAP_SUCCESS) {
        ldap_search_ext_s(ld, dn, LDAP_SCOPE_BASE, NULL, NULL, 0, NULL, NULL, NULL, 0, NULL);
    }
}
`
	flows := Analyze(code, "/app/ldap_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLDAP {
			t.Error("expected NO LDAP injection flow when DN is validated via ldap_str2dn")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// ==========================================================================
// C regex-DoS escaping sanitizer tests (GLib g_regex_escape_string, CWE-1333)
// ==========================================================================

// Positive control: a tainted pattern compiled directly with g_regex_new must
// produce a SnkRegexDoS flow (catastrophic-backtracking ReDoS).
func TestC_GRegexNew_Unsanitized_RegexDoS(t *testing.T) {
	code := `
#include <glib.h>
#include <stdlib.h>

void compile_user_regex() {
    char *pattern = getenv("USER_PATTERN");
    GError *err = NULL;
    GRegex *re = g_regex_new(pattern, 0, 0, &err);
}
`
	flows := Analyze(code, "/app/regex_vuln.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow when tainted pattern goes directly to g_regex_new")
	}
}

// g_regex_escape_string escapes all regex metacharacters, so the tainted input
// becomes a literal substring and the compiled pattern cannot backtrack.
func TestC_GRegexEscapeString_Sanitizes_RegexDoS(t *testing.T) {
	code := `
#include <glib.h>
#include <stdlib.h>

void compile_user_regex() {
    char *pattern = getenv("USER_PATTERN");
    gchar *safe = g_regex_escape_string(pattern, -1);
    GError *err = NULL;
    GRegex *re = g_regex_new(safe, 0, 0, &err);
}
`
	flows := Analyze(code, "/app/regex_safe.c", rules.LangC)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRegexDoS {
			t.Error("expected NO ReDoS flow when pattern is escaped via g_regex_escape_string")
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
