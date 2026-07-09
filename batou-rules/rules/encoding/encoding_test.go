package encoding

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// BATOU-ENC-007: Mixed encoding in SQL query
// ---------------------------------------------------------------------------

func TestENC007_TP_CharConcat(t *testing.T) {
	content := `query = "SELECT * FROM users WHERE name = " + CHAR(39) + name + CHAR(39)
db.execute(query)
`
	result := testutil.ScanContent(t, "/app/db.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-007")
}

func TestENC007_TP_UnhexInSelect(t *testing.T) {
	content := `cursor.execute("SELECT id FROM accounts WHERE token = UNHEX('48656c6c6f')")`
	result := testutil.ScanContent(t, "/app/repo.py", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-007")
}

func TestENC007_TP_HexLiteralWithSQLKeyword(t *testing.T) {
	content := `sql := "SELECT * FROM logs WHERE marker = 0x48656c6c6f"`
	result := testutil.ScanContent(t, "/app/store.go", content)
	testutil.MustFindRule(t, result, "BATOU-ENC-007")
}

// owncloud/web FP regression: an ES-module import line ending in a path
// whose final segment ends with 'x' (e.g. './index') used to match the
// reMixedEncodingSQL pattern because its trailing `X['"]` alternative
// matched any `x'` byte pair and case-insensitive `FROM` matched `from`.
func TestENC007_FP_ESModuleImport(t *testing.T) {
	content := `import store from './index'
import { useResources } from '../composables/useResources'
import config from '../config/prefix'
export const router = createRouter()
`
	result := testutil.ScanContent(t, "/app/main.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-007")
}

func TestENC007_FP_ImageDimensionString(t *testing.T) {
	// '5000x3000' contains the substring '0x3000'; the SQL-keyword gate is
	// word-boundary based, so a line that merely mentions a *Selector*
	// (containing "select") must not satisfy it.
	content := `const maxDimensions = '5000x3000'
const previewSelector = '.thumbnail-preview'
`
	result := testutil.ScanContent(t, "/app/preview.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-007")
}

func TestENC007_FP_HexLiteralNoSQLContext(t *testing.T) {
	content := `const COLOR_MASK = 0xff00ff
const flags = 0xdeadbeef
`
	result := testutil.ScanContent(t, "/app/colors.ts", content)
	testutil.MustNotFindRule(t, result, "BATOU-ENC-007")
}
