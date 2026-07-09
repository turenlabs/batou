package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Second-order injection through embedded key/value store reads.
// A value written earlier (potentially by an attacker) is read back from
// LevelDB/RocksDB/GDBM/NDBM and flows unsanitized into a dangerous sink.

func TestC_LevelDBGet_ToCommand(t *testing.T) {
	code := `
#include <leveldb/c.h>
#include <stdlib.h>

void run_cached(leveldb_t *db, leveldb_readoptions_t *ro, const char *key) {
    size_t vallen;
    char *err = NULL;
    char *val = leveldb_get(db, ro, key, strlen(key), &vallen, &err);
    system(val);
}
`
	flows := Analyze(code, "/app/leveldb_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for leveldb_get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_RocksDBGet_ToCommand(t *testing.T) {
	code := `
#include <rocksdb/c.h>
#include <stdlib.h>

void run_cached(rocksdb_t *db, rocksdb_readoptions_t *ro, const char *key) {
    size_t vallen;
    char *err = NULL;
    char *val = rocksdb_get(db, ro, key, strlen(key), &vallen, &err);
    system(val);
}
`
	flows := Analyze(code, "/app/rocksdb_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rocksdb_get -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_RocksDBGetCF_ToCommand(t *testing.T) {
	code := `
#include <rocksdb/c.h>
#include <stdlib.h>

void run_cached(rocksdb_t *db, rocksdb_readoptions_t *ro, rocksdb_column_family_handle_t *cf, const char *key) {
    size_t vallen;
    char *err = NULL;
    char *val = rocksdb_get_cf(db, ro, cf, key, strlen(key), &vallen, &err);
    system(val);
}
`
	flows := Analyze(code, "/app/rocksdb_cf_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for rocksdb_get_cf -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_GDBMFetch_ToCommand(t *testing.T) {
	code := `
#include <gdbm.h>
#include <stdlib.h>

void run_cached(GDBM_FILE dbf, datum key) {
    datum val = gdbm_fetch(dbf, key);
    system(val.dptr);
}
`
	flows := Analyze(code, "/app/gdbm_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for gdbm_fetch -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestC_NDBMFetch_ToCommand(t *testing.T) {
	code := `
#include <ndbm.h>
#include <stdlib.h>

void run_cached(DBM *db, datum key) {
    datum val = dbm_fetch(db, key);
    system(val.dptr);
}
`
	flows := Analyze(code, "/app/ndbm_exec.c", rules.LangC)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for dbm_fetch -> system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant key/value store read with a hardcoded literal
// must NOT produce a flow (no taint introduced).
func TestC_LevelDBGet_ConstantNoFlow(t *testing.T) {
	code := `
#include <leveldb/c.h>
#include <stdlib.h>

void run_cfg(leveldb_t *db, leveldb_readoptions_t *ro) {
    system("/usr/bin/refresh-cache");
}
`
	flows := Analyze(code, "/app/leveldb_const.c", rules.LangC)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a command flow for a constant command string")
	}
}
