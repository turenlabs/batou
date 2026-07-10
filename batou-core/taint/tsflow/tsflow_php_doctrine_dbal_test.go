package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// PHP — Doctrine DBAL Connection modern fetch/iterate/execute methods
// =========================================================================
//
// Doctrine DBAL Connection (the most-used PHP database abstraction; backbone
// of Symfony, API Platform, Sylius, Akeneo) exposes ~14 methods that all take
// a raw SQL string at arg 0. Tainted SQL flowing into any of these is SQLi
// regardless of whether placeholder bindings are used at args 1+ — placeholders
// bind parameter VALUES, not the SQL string. These tests exercise each new
// catalog entry plus a negative test confirming constant SQL does NOT flow.

func TestPHP_DoctrineDBAL_ExecuteQuery_SQLInjection(t *testing.T) {
	code := `<?php
function listUsers($conn) {
    $name = $_GET['name'];
    $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
    $conn->executeQuery($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_GET -> concat -> Connection::executeQuery")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}

func TestPHP_DoctrineDBAL_FetchAllAssociative_SQLInjection(t *testing.T) {
	code := `<?php
function listUsers($conn) {
    $name = $_POST['name'];
    $sql = "SELECT * FROM users WHERE name = '" . $name . "'";
    return $conn->fetchAllAssociative($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_POST -> concat -> Connection::fetchAllAssociative")
	}
}

func TestPHP_DoctrineDBAL_FetchAssociative_SQLInjection(t *testing.T) {
	code := `<?php
function findUser($conn) {
    $id = $_REQUEST['id'];
    $sql = "SELECT * FROM users WHERE id = " . $id;
    return $conn->fetchAssociative($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for $_REQUEST -> concat -> Connection::fetchAssociative")
	}
}

func TestPHP_DoctrineDBAL_FetchAllNumeric_SQLInjection(t *testing.T) {
	code := `<?php
function listOrders($conn) {
    $col = $_GET['col'];
    $sql = "SELECT " . $col . " FROM orders";
    return $conn->fetchAllNumeric($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/OrderRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::fetchAllNumeric")
	}
}

func TestPHP_DoctrineDBAL_FetchNumeric_SQLInjection(t *testing.T) {
	code := `<?php
function getUserRow($conn) {
    $id = $_GET['id'];
    $sql = "SELECT id, name FROM users WHERE id = " . $id;
    return $conn->fetchNumeric($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::fetchNumeric")
	}
}

func TestPHP_DoctrineDBAL_FetchAllKeyValue_SQLInjection(t *testing.T) {
	code := `<?php
function getMap($conn) {
    $tbl = $_GET['tbl'];
    $sql = "SELECT id, name FROM " . $tbl;
    return $conn->fetchAllKeyValue($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/MapRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::fetchAllKeyValue")
	}
}

func TestPHP_DoctrineDBAL_FetchAllAssociativeIndexed_SQLInjection(t *testing.T) {
	code := `<?php
function getIndexed($conn) {
    $where = $_GET['where'];
    $sql = "SELECT id, name, email FROM users WHERE " . $where;
    return $conn->fetchAllAssociativeIndexed($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::fetchAllAssociativeIndexed")
	}
}

func TestPHP_DoctrineDBAL_FetchOne_SQLInjection(t *testing.T) {
	code := `<?php
function getCount($conn) {
    $tbl = $_GET['tbl'];
    $sql = "SELECT COUNT(*) FROM " . $tbl;
    return $conn->fetchOne($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/CountRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::fetchOne")
	}
}

func TestPHP_DoctrineDBAL_FetchFirstColumn_SQLInjection(t *testing.T) {
	code := `<?php
function listIds($conn) {
    $tbl = $_GET['tbl'];
    $sql = "SELECT id FROM " . $tbl;
    return $conn->fetchFirstColumn($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/IdRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::fetchFirstColumn")
	}
}

func TestPHP_DoctrineDBAL_IterateAssociative_SQLInjection(t *testing.T) {
	code := `<?php
function streamUsers($conn) {
    $where = $_GET['where'];
    $sql = "SELECT * FROM users WHERE " . $where;
    foreach ($conn->iterateAssociative($sql) as $row) {
        yield $row;
    }
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserStreamRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::iterateAssociative")
	}
}

func TestPHP_DoctrineDBAL_IterateNumeric_SQLInjection(t *testing.T) {
	code := `<?php
function streamRows($conn) {
    $tbl = $_GET['tbl'];
    $sql = "SELECT id, name FROM " . $tbl;
    foreach ($conn->iterateNumeric($sql) as $row) {
        echo $row[0];
    }
}
?>`
	flows := Analyze(code, "/app/src/Repository/StreamRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::iterateNumeric")
	}
}

func TestPHP_DoctrineDBAL_IterateColumn_SQLInjection(t *testing.T) {
	code := `<?php
function streamColumn($conn) {
    $col = $_GET['col'];
    $sql = "SELECT " . $col . " FROM users";
    foreach ($conn->iterateColumn($sql) as $val) {
        echo $val;
    }
}
?>`
	flows := Analyze(code, "/app/src/Repository/ColumnRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::iterateColumn")
	}
}

func TestPHP_DoctrineDBAL_IterateKeyValue_SQLInjection(t *testing.T) {
	code := `<?php
function streamMap($conn) {
    $tbl = $_GET['tbl'];
    $sql = "SELECT id, name FROM " . $tbl;
    foreach ($conn->iterateKeyValue($sql) as $k => $v) {
        echo "$k => $v";
    }
}
?>`
	flows := Analyze(code, "/app/src/Repository/MapStreamRepository.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow via Connection::iterateKeyValue")
	}
}

// --- Negative test: constant SQL should NOT produce a flow ---

func TestPHP_DoctrineDBAL_FetchAssociative_ConstantSQL_NoFlow(t *testing.T) {
	code := `<?php
function getActiveCount($conn) {
    $sql = "SELECT COUNT(*) FROM users WHERE active = 1";
    return $conn->fetchOne($sql);
}
?>`
	flows := Analyze(code, "/app/src/Repository/UserRepository.php", rules.LangPHP)
	if hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("did not expect SQL injection flow for constant SQL into Connection::fetchOne")
		for _, f := range flows {
			t.Logf("  spurious flow: %s -> %s (id=%s)", f.Source.Category, f.Sink.Category, f.Sink.ID)
		}
	}
}
