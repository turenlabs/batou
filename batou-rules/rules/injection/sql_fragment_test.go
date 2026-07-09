package injection

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// inj027Finding returns the BATOU-INJ-027 finding from a scan, or nil.
func inj027Finding(result *testutil.ScanResult) *rules.Finding {
	fs := testutil.FindingsByRule(result, "BATOU-INJ-027")
	if len(fs) == 0 {
		return nil
	}
	return &fs[0]
}

// --- E6-T4: BATOU-INJ-027 must NOT fire on non-SQL interpolations ---
//
// owncloud/web scan (2026-04-24) produced 16 mostly-CRITICAL findings on
// DOM selectors, Vue dependency-injection keys, and log/error messages —
// backtick or single-quoted strings that merely contain an interpolation
// but are not SQL fragments. The keyword-proximity gate kills these.

func TestINJ027_DOMSelector_NoFP(t *testing.T) {
	for _, code := range []string{
		"const els = document.querySelectorAll(`[data-item='${id}']`);",
		"const row = el.querySelector(`tr[data-id='${rowId}']`);",
		"const node = container.querySelector(`[role='listitem'][aria-label='${label}']`);",
		"el.closest(`[data-resource='${name}']`);",
	} {
		res := testutil.ScanContent(t, "/app/components/ResourceTable.ts", code)
		if f := inj027Finding(res); f != nil {
			t.Errorf("did not expect BATOU-INJ-027 on DOM selector %q (line %d, %q)", code, f.LineNumber, f.MatchedText)
		}
	}
}

func TestINJ027_VueDIKey_NoFP(t *testing.T) {
	for _, code := range []string{
		"const svc = useService('${appProviderService}');",
		"const store = inject('${userStore}');",
		"provide('${configToken}', cfg);",
	} {
		res := testutil.ScanContent(t, "/app/services/di.ts", code)
		if f := inj027Finding(res); f != nil {
			t.Errorf("did not expect BATOU-INJ-027 on DI key %q (line %d, %q)", code, f.LineNumber, f.MatchedText)
		}
	}
}

func TestINJ027_LogMessage_NoFP(t *testing.T) {
	for _, code := range []string{
		"logger.info(`processed '${count}' records, '${failed}' failed`);",
		"console.warn(`retry '${attempt}' for '${name}'`);",
		"throw new Error(`Resource with key '${key}' not found`);",
		"this.$log.debug(`state changed to '${next}'`);",
	} {
		res := testutil.ScanContent(t, "/app/util/logging.ts", code)
		if f := inj027Finding(res); f != nil {
			t.Errorf("did not expect BATOU-INJ-027 on log message %q (line %d, %q)", code, f.LineNumber, f.MatchedText)
		}
	}
}

// Import lines near a `$`-string must not push a non-SQL line over the bar
// (their `from './x'` clause collides with the SQL FROM marker).
func TestINJ027_ImportContext_NoFP(t *testing.T) {
	code := "import { Resource } from './resource';\n" +
		"const sel = `[data-id='${id}']`;\n" +
		"import { Drive } from './drive';\n"
	res := testutil.ScanContent(t, "/app/components/Foo.ts", code)
	if f := inj027Finding(res); f != nil {
		t.Errorf("did not expect BATOU-INJ-027 with import context, got line %d %q", f.LineNumber, f.MatchedText)
	}
}

// --- E6-T4: BATOU-INJ-027 must STILL fire on real SQL fragment injection ---

func TestINJ027_RealSQLTemplate_FiresCritical(t *testing.T) {
	res := testutil.ScanContent(t, "/app/db/users.js",
		"const q = `SELECT id, name FROM users WHERE email = '${email}'`;")
	f := inj027Finding(res)
	if f == nil {
		t.Fatalf("expected BATOU-INJ-027 on real SQL template literal; findings=%v", testutil.FindingRuleIDs(res))
	}
	if f.Severity != rules.Critical {
		t.Errorf("expected CRITICAL severity, got %v", f.Severity)
	}
}

func TestINJ027_RealSQLConcat_FiresCritical(t *testing.T) {
	// Single-quote-concat SQL fragment (the shape INJ-027 specialises in —
	// it does not contain SELECT at the top so the main SQLi rule may miss it).
	res := testutil.ScanContent(t, "/app/db/search.js",
		"const where = ' WHERE name = ' + name + ' AND tenant_id = ' + tid;")
	f := inj027Finding(res)
	if f == nil {
		t.Fatalf("expected BATOU-INJ-027 on real SQL concat fragment; findings=%v", testutil.FindingRuleIDs(res))
	}
	if f.Severity != rules.Critical {
		t.Errorf("expected CRITICAL severity, got %v", f.Severity)
	}
}

// ORDER BY / GROUP BY interpolation is a real injection (cannot be
// parameterised) — must still fire.
func TestINJ027_OrderByInterp_Fires(t *testing.T) {
	res := testutil.ScanContent(t, "/app/db/list.js",
		"const frag = ' ORDER BY ' + sortCol + ' ' + sortDir;")
	if inj027Finding(res) == nil {
		t.Fatalf("expected BATOU-INJ-027 on ORDER BY interpolation; findings=%v", testutil.FindingRuleIDs(res))
	}
}

// Ghost CVE-2026-26980 style: a SQL fragment with no top-level keyword but
// MySQL backtick-quoted identifiers and a quoted-value comparison. Detected
// via the marker fallback in hasSQLEvidenceNearInterp.
func TestINJ027_GhostStyleFragment_Fires(t *testing.T) {
	res := testutil.ScanContent(t, "/app/models/post.js",
		"order += ' WHEN `slug` = '+slug+' THEN '+index+' ';")
	if inj027Finding(res) == nil {
		t.Fatalf("expected BATOU-INJ-027 on Ghost-style fragment; findings=%v", testutil.FindingRuleIDs(res))
	}
}
