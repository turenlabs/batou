package eval

// Import rule packages and taint catalogs to trigger init() registrations
// for the test binary. Without these, the scanner has no rules to run.
import (
	_ "github.com/turenio/gtss/internal/analyzer/goast"
	_ "github.com/turenio/gtss/internal/rules/auth"
	_ "github.com/turenio/gtss/internal/rules/crypto"
	_ "github.com/turenio/gtss/internal/rules/generic"
	_ "github.com/turenio/gtss/internal/rules/injection"
	_ "github.com/turenio/gtss/internal/rules/logging"
	_ "github.com/turenio/gtss/internal/rules/memory"
	_ "github.com/turenio/gtss/internal/rules/secrets"
	_ "github.com/turenio/gtss/internal/rules/ssrf"
	_ "github.com/turenio/gtss/internal/rules/traversal"
	_ "github.com/turenio/gtss/internal/rules/validation"
	_ "github.com/turenio/gtss/internal/rules/xss"
	_ "github.com/turenio/gtss/internal/taint"
	_ "github.com/turenio/gtss/internal/taint/goflow"
	_ "github.com/turenio/gtss/internal/taint/languages"
)
