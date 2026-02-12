package eval

// Import rule packages and taint catalogs to trigger init() registrations
// for the test binary. Without these, the scanner has no rules to run.
import (
	_ "github.com/turen/gtss/internal/analyzer/goast"
	_ "github.com/turen/gtss/internal/rules/auth"
	_ "github.com/turen/gtss/internal/rules/crypto"
	_ "github.com/turen/gtss/internal/rules/generic"
	_ "github.com/turen/gtss/internal/rules/injection"
	_ "github.com/turen/gtss/internal/rules/logging"
	_ "github.com/turen/gtss/internal/rules/memory"
	_ "github.com/turen/gtss/internal/rules/secrets"
	_ "github.com/turen/gtss/internal/rules/ssrf"
	_ "github.com/turen/gtss/internal/rules/traversal"
	_ "github.com/turen/gtss/internal/rules/validation"
	_ "github.com/turen/gtss/internal/rules/xss"
	_ "github.com/turen/gtss/internal/taint"
	_ "github.com/turen/gtss/internal/taint/goflow"
	_ "github.com/turen/gtss/internal/taint/languages"
)
