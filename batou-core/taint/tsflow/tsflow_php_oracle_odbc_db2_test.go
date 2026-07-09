package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// PHP Oracle (OCI8) / ODBC / IBM DB2 raw-SQL injection sinks (CWE-89).
//
// PHP modeled MySQL, PgSQL, SQLite and SQL Server SQLi sinks but not the
// three other official PHP database extensions that execute a verbatim SQL
// string: Oracle's oci_parse(), ODBC's odbc_exec()/odbc_prepare(), and IBM
// DB2's db2_exec()/db2_prepare(). In every one of them the connection is
// arg 0 and the SQL/statement string is arg 1 (DangerousArgs: []int{1}),
// mirroring the existing sqlsrv_query() entry. These tests lock in
// detection of a tainted superglobal reaching each function, plus an
// FP-safe negative for a constant statement.
// =========================================================================

// --- Oracle OCI8: oci_parse($conn, $sql) ---

func TestPHP_Oracle_OCIParse_SQLi(t *testing.T) {
	code := `<?php
$id = $_GET['id'];
$sql = "SELECT * FROM accounts WHERE id = " . $id;
$stmt = oci_parse($conn, $sql);
oci_execute($stmt);`
	flows := Analyze(code, "/var/www/oracle.php", rules.LangPHP)
	if !hasFlowFromSink(flows, "php.oci_parse", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow $_GET -> oci_parse() (arg 1)")
	}
}

// --- ODBC: odbc_exec($conn, $query) ---

func TestPHP_ODBC_Exec_SQLi(t *testing.T) {
	code := `<?php
$name = $_POST['name'];
$query = "SELECT * FROM staff WHERE name = '" . $name . "'";
$res = odbc_exec($conn, $query);`
	flows := Analyze(code, "/var/www/odbc.php", rules.LangPHP)
	if !hasFlowFromSink(flows, "php.odbc_exec", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow $_POST -> odbc_exec() (arg 1)")
	}
}

// --- ODBC: odbc_prepare($conn, $query) ---

func TestPHP_ODBC_Prepare_SQLi(t *testing.T) {
	code := `<?php
$dept = $_GET['dept'];
$query = "SELECT * FROM staff WHERE dept = '" . $dept . "'";
$stmt = odbc_prepare($conn, $query);
odbc_execute($stmt);`
	flows := Analyze(code, "/var/www/odbc.php", rules.LangPHP)
	if !hasFlowFromSink(flows, "php.odbc_prepare", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow $_GET -> odbc_prepare() (arg 1)")
	}
}

// --- IBM DB2: db2_exec($conn, $stmt) ---

func TestPHP_DB2_Exec_SQLi(t *testing.T) {
	code := `<?php
$uid = $_REQUEST['uid'];
$sql = "SELECT * FROM users WHERE uid = " . $uid;
$res = db2_exec($conn, $sql);`
	flows := Analyze(code, "/var/www/db2.php", rules.LangPHP)
	if !hasFlowFromSink(flows, "php.db2_exec", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow $_REQUEST -> db2_exec() (arg 1)")
	}
}

// --- IBM DB2: db2_prepare($conn, $stmt) ---

func TestPHP_DB2_Prepare_SQLi(t *testing.T) {
	code := `<?php
$q = $_GET['q'];
$sql = "SELECT * FROM products WHERE sku = '" . $q . "'";
$stmt = db2_prepare($conn, $sql);
db2_execute($stmt);`
	flows := Analyze(code, "/var/www/db2.php", rules.LangPHP)
	if !hasFlowFromSink(flows, "php.db2_prepare", taint.SnkSQLQuery) {
		t.Error("expected SQLi flow $_GET -> db2_prepare() (arg 1)")
	}
}

// --- Negative control: constant statement, no taint reaches the sink ---

func TestPHP_Oracle_ODBC_DB2_ConstantStmt_NoFlow(t *testing.T) {
	code := `<?php
$sql = "SELECT * FROM accounts WHERE active = 1";
$s1 = oci_parse($conn, $sql);
$s2 = odbc_exec($conn, $sql);
$s3 = db2_exec($conn, $sql);`
	flows := Analyze(code, "/var/www/safe.php", rules.LangPHP)
	if hasFlowFromSink(flows, "php.oci_parse", taint.SnkSQLQuery) ||
		hasFlowFromSink(flows, "php.odbc_exec", taint.SnkSQLQuery) ||
		hasFlowFromSink(flows, "php.db2_exec", taint.SnkSQLQuery) {
		t.Error("constant SQL statement must not produce a SQLi flow")
	}
}
