package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// C database source tests (SrcDatabase)
// =========================================================================

func TestC_SQLite3ColumnText_ToCommand(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <stdlib.h>

void run_stored_cmd(sqlite3_stmt *stmt) {
    const char *cmd = sqlite3_column_text(stmt, 0);
    system(cmd);
}
`
	flows := Analyze(code, "/app/db_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for sqlite3_column_text -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SQLite3ColumnBlob_ToFileWrite(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <stdio.h>

void write_blob(sqlite3_stmt *stmt) {
    const void *data = sqlite3_column_blob(stmt, 0);
    FILE *f = fopen("/tmp/output", "wb");
    fwrite(data, 1, 1024, f);
}
`
	flows := Analyze(code, "/app/blob_write.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for sqlite3_column_blob -> fwrite")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_MySQLFetchRow_ToSystem(t *testing.T) {
	code := `
#include <mysql/mysql.h>
#include <stdlib.h>

void exec_stored(MYSQL_RES *result) {
    MYSQL_ROW row = mysql_fetch_row(result);
    system(row[0]);
}
`
	flows := Analyze(code, "/app/db_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for mysql_fetch_row -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_PQGetvalue_ToSystem(t *testing.T) {
	code := `
#include <libpq-fe.h>
#include <stdlib.h>

void exec_stored_cmd(PGresult *res) {
    char *cmd = PQgetvalue(res, 0, 0);
    system(cmd);
}
`
	flows := Analyze(code, "/app/pg_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for PQgetvalue -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_SQLite3ColumnDouble_ToSprintf(t *testing.T) {
	code := `
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>

void log_value(sqlite3_stmt *stmt) {
    double val = sqlite3_column_double(stmt, 0);
    char buf[256];
    sprintf(buf, "%f", val);
    system(buf);
}
`
	flows := Analyze(code, "/app/db_double.c", rules.LangC)
	// The database value reaches sprintf, which writes into a fixed buffer —
	// that is a memory-write sink (CWE-120 / SnkMemory), NOT command_exec. This
	// test previously asserted SnkCommand, but that only passed because sprintf
	// was mislabeled as SnkCommand in the C catalog; the engine never actually
	// propagated the taint through buf into the trailing system() call. With
	// sprintf correctly categorized SnkMemory, the genuine database->buffer flow
	// is what fires. (system() with a "%f"-formatted double is not injectable
	// anyway — only digits and a dot reach the shell.)
	if !hasTaintFlow(flows, taint.SnkMemory) {
		t.Error("expected memory-write flow for sqlite3_column_double -> sprintf (buffer write)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C deserialization source tests (SrcDeserialized)
// =========================================================================

func TestC_cJSON_Parse_ToSystem(t *testing.T) {
	code := `
#include <cJSON.h>
#include <stdlib.h>

void handle_json(const char *input) {
    cJSON *root = cJSON_Parse(input);
    cJSON *cmd = cJSON_GetObjectItem(root, "command");
    char *val = cJSON_GetStringValue(cmd);
    system(val);
}
`
	flows := Analyze(code, "/app/json_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for cJSON_Parse -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Jansson_ToSystem(t *testing.T) {
	code := `
#include <jansson.h>
#include <stdlib.h>

void handle_json(const char *input) {
    json_t *root = json_loads(input, 0, NULL);
    json_t *cmd_obj = json_object_get(root, "cmd");
    const char *cmd = json_string_value(cmd_obj);
    system(cmd);
}
`
	flows := Analyze(code, "/app/jansson_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for json_loads -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_JsonC_ToSystem(t *testing.T) {
	code := `
#include <json-c/json.h>
#include <stdlib.h>

void handle_json(const char *input) {
    struct json_object *root = json_tokener_parse(input);
    const char *val = json_object_get_string(root);
    system(val);
}
`
	flows := Analyze(code, "/app/jsonc_cmd.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for json_tokener_parse -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe patterns — no flows expected
// =========================================================================

func TestC_SQLite3_Safe_Literal(t *testing.T) {
	code := `
#include <stdlib.h>

void run_safe() {
    const char *cmd = "ls -la";
    system(cmd);
}
`
	flows := Analyze(code, "/app/safe_literal.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow when command is a literal, not from database")
	}
}

// =========================================================================
// C deserialization SINK tests (SnkDeserialize)
// =========================================================================

func TestC_cJSON_Parse_DeserSink(t *testing.T) {
	code := `
#include <cJSON.h>
#include <stdlib.h>

void handle_request() {
    char *data = getenv("JSON_INPUT");
    cJSON *root = cJSON_Parse(data);
}
`
	flows := Analyze(code, "/app/deser_cjson.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> cJSON_Parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Jansson_Loads_DeserSink(t *testing.T) {
	code := `
#include <jansson.h>
#include <stdlib.h>

void handle_request() {
    char *data = getenv("JSON_INPUT");
    json_error_t err;
    json_t *root = json_loads(data, 0, &err);
}
`
	flows := Analyze(code, "/app/deser_jansson.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> json_loads")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_JsonC_Parse_DeserSink(t *testing.T) {
	code := `
#include <json-c/json.h>
#include <stdlib.h>

void handle_request() {
    char *data = getenv("JSON_INPUT");
    struct json_object *obj = json_tokener_parse(data);
}
`
	flows := Analyze(code, "/app/deser_jsonc.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> json_tokener_parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Yajl_Parse_DeserSink(t *testing.T) {
	code := `
#include <yajl/yajl_parse.h>
#include <stdlib.h>

void handle_request(yajl_handle hand) {
    char *data = getenv("JSON_INPUT");
    yajl_parse(hand, data, 256);
}
`
	flows := Analyze(code, "/app/deser_yajl.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> yajl_parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Msgpack_Unpack_DeserSink(t *testing.T) {
	code := `
#include <msgpack.h>
#include <stdlib.h>

void handle_request() {
    char *data = getenv("MSGPACK_INPUT");
    msgpack_unpacked result;
    msgpack_unpacked_init(&result);
    msgpack_unpack(data, 256, NULL, &result.zone, &result.data);
}
`
	flows := Analyze(code, "/app/deser_msgpack.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> msgpack_unpack")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Expat_Parse_DeserSink(t *testing.T) {
	code := `
#include <expat.h>
#include <stdlib.h>

void handle_request(XML_Parser parser) {
    char *data = getenv("XML_INPUT");
    XML_Parse(parser, data, 256, 1);
}
`
	flows := Analyze(code, "/app/deser_expat.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> XML_Parse")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_Jansson_LoadFile_DeserSink(t *testing.T) {
	code := `
#include <jansson.h>
#include <stdio.h>

void load_config(const char *user_path) {
    char *path = getenv("CONFIG_PATH");
    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
}
`
	flows := Analyze(code, "/app/deser_loadfile.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> json_load_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_JsonC_FromFile_DeserSink(t *testing.T) {
	code := `
#include <json-c/json.h>
#include <stdlib.h>

void load_config() {
    char *path = getenv("JSON_PATH");
    struct json_object *obj = json_object_from_file(path);
}
`
	flows := Analyze(code, "/app/deser_jsonc_file.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected deserialization sink flow for getenv -> json_object_from_file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// C deserialization sanitizer tests
// =========================================================================

func TestC_Deser_XMLSchemaValidate_Safe(t *testing.T) {
	code := `
#include <libxml/xmlschemastypes.h>
#include <libxml/parser.h>
#include <unistd.h>

void handle_request(int fd) {
    char buf[4096];
    read(fd, buf, sizeof(buf));
    xmlDocPtr doc = xmlParseMemory(buf, sizeof(buf));
    xmlSchemaValidateDoc(schema_ctx, doc);
}
`
	flows := Analyze(code, "/app/deser_safe_schema.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when xmlSchemaValidateDoc sanitizes the parse")
	}
}

func TestC_Deser_JanssonUnpackEx_Safe(t *testing.T) {
	code := `
#include <jansson.h>
#include <unistd.h>

void handle_request(int fd) {
    char buf[4096];
    read(fd, buf, sizeof(buf));
    json_error_t err;
    json_t *root = json_loads(buf, 0, &err);
    int id;
    const char *name;
    json_unpack_ex(root, &err, 0, "{s:i, s:s}", "id", &id, "name", &name);
}
`
	flows := Analyze(code, "/app/deser_safe_unpack.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when json_unpack_ex validates the structure")
	}
}

func TestC_cJSON_Safe_Sanitized(t *testing.T) {
	code := `
#include <cJSON.h>
#include <stdio.h>

void handle_json_safe(const char *input) {
    cJSON *root = cJSON_Parse(input);
    cJSON *count = cJSON_GetObjectItem(root, "count");
    int val = atoi(cJSON_GetStringValue(count));
    printf("Count: %d\n", val);
}
`
	flows := Analyze(code, "/app/json_safe.c", rules.LangC)
	// atoi converts to integer, no string taint reaches a dangerous sink
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO command injection flow when value is converted to int via atoi")
	}
}

// =========================================================================
// C new sanitizer tests
// =========================================================================

func TestC_Deser_ExpatEntityHandler_Safe(t *testing.T) {
	code := `
#include <expat.h>
#include <unistd.h>

void handle_xml(int fd) {
    char buf[4096];
    read(fd, buf, sizeof(buf));
    XML_Parser parser = XML_ParserCreate(NULL);
    XML_SetEntityDeclHandler(parser, entity_handler);
    XML_Parse(parser, buf, sizeof(buf), 1);
}
`
	flows := Analyze(code, "/app/expat_safe_entity.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when XML_SetEntityDeclHandler is used")
	}
}

func TestC_Deser_ExpatExternalEntityHandler_Safe(t *testing.T) {
	code := `
#include <expat.h>
#include <unistd.h>

void handle_xml(int fd) {
    char buf[4096];
    read(fd, buf, sizeof(buf));
    XML_Parser parser = XML_ParserCreate(NULL);
    XML_SetExternalEntityRefHandler(parser, ext_entity_handler);
    XML_Parse(parser, buf, sizeof(buf), 1);
}
`
	flows := Analyze(code, "/app/expat_safe_external.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when XML_SetExternalEntityRefHandler is used")
	}
}

func TestC_Deser_cJSONParseWithLength_Safe(t *testing.T) {
	code := `
#include <cJSON.h>
#include <stdlib.h>

void handle_json() {
    char *data = getenv("JSON_INPUT");
    cJSON *root = cJSON_ParseWithLength(data, 1024);
}
`
	flows := Analyze(code, "/app/cjson_safe_bounded.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when cJSON_ParseWithLength bounds the input")
	}
}

func TestC_Deser_JsonTokenerSetFlags_Safe(t *testing.T) {
	code := `
#include <json-c/json.h>
#include <stdlib.h>

void handle_json() {
    char *data = getenv("JSON_INPUT");
    struct json_tokener *tok = json_tokener_new();
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    struct json_object *obj = json_tokener_parse_ex(tok, data, -1);
}
`
	flows := Analyze(code, "/app/jsonc_safe_strict.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkDeserialize) {
		t.Error("expected NO deserialization flow when json_tokener_set_flags enables strict mode")
	}
}

func TestC_LDAP_Bv2Escaped_Safe(t *testing.T) {
	code := `
#include <ldap.h>
#include <stdlib.h>

void search_user() {
    char *input = getenv("USER_INPUT");
    struct berval in = { strlen(input), input };
    struct berval *escaped = NULL;
    ldap_bv2escaped_filter_value(&in, escaped);
    ldap_search_ext_s(ld, base, LDAP_SCOPE_SUBTREE, escaped->bv_val, NULL, 0, NULL, NULL, NULL, 0, &result);
}
`
	flows := Analyze(code, "/app/ldap_safe_escape.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkLDAP) {
		t.Error("expected NO LDAP injection flow when ldap_bv2escaped_filter_value sanitizes input")
	}
}

func TestC_URL_MgUrlEncode_Safe(t *testing.T) {
	code := `
#include <mongoose.h>
#include <stdlib.h>

void handle_redirect() {
    char *url = getenv("REDIRECT_URL");
    char encoded[1024];
    mg_url_encode(url, strlen(url), encoded, sizeof(encoded));
    mg_http_reply(conn, 302, "Location: %s\r\n", encoded);
}
`
	flows := Analyze(code, "/app/mg_safe_redirect.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected NO redirect flow when mg_url_encode sanitizes the URL")
	}
}
