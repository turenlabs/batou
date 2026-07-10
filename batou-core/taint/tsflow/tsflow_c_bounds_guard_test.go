package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Regression: C/C++ memory-copy bounds-guard recogniser (c_bounds_guard.go).
//
// Real-world FP (smoke test, redis-redis/src): blocking-tier
// BATOU-TAINT-memory_write findings on memcpy/strcpy calls whose copy length is
// constrained by an early-exit size check on the immediately-preceding line(s):
//
//   if (sdslen(o->ptr) > sizeof(buf)-1) goto invalid;   // t_stream.c:2383
//   if (strlen(filepath) > PATH_MAX) goto invalid_args; // redis-check-aof.c:566
//   if (*used + sizeof(payloadHeader) + len > size) return 0; // networking.c:378
//   if (sdslen(parts[idx]) != CLUSTER_NAMELEN) goto err;     // cluster_asm.c:480
//   if (strlen(argv[1]) != CONFIG_RUN_ID_SIZE) return ...;   // sentinel.c:1926
//
// Each is a bounded copy — the out-of-bounds-write finding is a false positive.
// The recogniser suppresses ONLY when the guard is an early-exit size
// comparison that references the copy's source or size, within a small lookback
// window. Every test pins BOTH directions: the guarded shape stops firing, and
// a genuinely unguarded copy of the same intrinsic STILL fires (tightened, not
// disabled).
// =========================================================================

// Guarded shapes mirrored from the Redis FP corpus must NOT fire SnkMemory.
func TestC_Memcpy_BoundsGuard_Suppressed(t *testing.T) {
	cases := map[string]string{
		"sizeof-1 guard (t_stream shape)": `
#include <string.h>
int parse(const char *o, int olen) {
    char buf[128];
    if (olen > sizeof(buf)-1) goto invalid;
    memcpy(buf, o, olen);
    return 0;
invalid:
    return -1;
}
`,
		"PATH_MAX guard (redis-check-aof shape)": `
#include <string.h>
#include <limits.h>
int check(const char *filepath, int len) {
    char temp[PATH_MAX];
    if (len > PATH_MAX) {
        return -1;
    }
    memcpy(temp, filepath, len);
    return 0;
}
`,
		"!= NAMELEN const guard (cluster_asm shape)": `
#include <string.h>
#define CLUSTER_NAMELEN 40
int loadtask(const char *parts, int plen, char *dest) {
    char source[CLUSTER_NAMELEN];
    if (plen != CLUSTER_NAMELEN) goto err;
    memcpy(source, parts, plen);
    return 0;
err:
    return -1;
}
`,
		"sizeof + len > size guard (networking shape)": `
#include <string.h>
typedef struct { int x; } payloadHeader;
int add(char *dst, const char *payload, unsigned len, unsigned size, unsigned used) {
    if (used + sizeof(payloadHeader) + len > size) return 0;
    memcpy(dst, payload, len);
    return 1;
}
`,
	}
	for name, code := range cases {
		flows := Analyze(code, "/app/redis.c", rules.LangC)
		if hasTaintFlow(flows, taint.SnkMemory) {
			t.Errorf("%s: bounds-guarded memcpy must NOT fire SnkMemory (memory_write FP)", name)
		}
	}
}

// A copy with no size guard — or one whose only preceding check is unrelated —
// must STILL fire SnkMemory: the recogniser tightens, it does not disable.
func TestC_Memcpy_Unguarded_StillFires(t *testing.T) {
	cases := map[string]string{
		"no guard": `
#include <string.h>
void copy(char *payload, int len) {
    char buf[256];
    memcpy(buf, payload, len);
}
`,
		// A non-size predicate (flag test) does not bound the copy length, so the
		// copy must still be flagged.
		"flag-check is not a size guard": `
#include <string.h>
void copy(char *payload, unsigned len, int flag) {
    char buf[256];
    if (flag == 0) return;
    memcpy(buf, payload, len);
}
`,
		// A size guard that constrains a DIFFERENT variable than the copy size,
		// placed far above the copy (outside the lookback window). Two independent
		// reasons it must NOT suppress: the guard references neither the source
		// nor the size, and it is beyond the lookback window.
		"unrelated size guard far above": `
#include <string.h>
void copy(char *payload, unsigned len, unsigned other) {
    char buf[256];
    if (other > sizeof(buf)) { return; }
    int x1=1;
    int x2=2;
    int x3=3;
    int x4=4;
    int x5=5;
    int x6=6;
    int x7=7;
    int x8=8;
    int x9=9;
    memcpy(buf, payload, len);
}
`,
	}
	for name, code := range cases {
		flows := Analyze(code, "/app/redis.c", rules.LangC)
		if !hasTaintFlow(flows, taint.SnkMemory) {
			t.Errorf("%s: unguarded memcpy must STILL fire SnkMemory (must tighten, not disable)", name)
		}
	}
}
