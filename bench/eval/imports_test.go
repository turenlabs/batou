package eval

// Import rule packages and taint catalogs to trigger init() registrations
// for the test binary. Without these, the scanner has no rules to run.
import (
	_ "github.com/turenlabs/batou/internal/analyzer/goast"
	_ "github.com/turenlabs/batou/internal/rules/auth"
	_ "github.com/turenlabs/batou/internal/rules/crypto"
	_ "github.com/turenlabs/batou/internal/rules/generic"
	_ "github.com/turenlabs/batou/internal/rules/injection"
	_ "github.com/turenlabs/batou/internal/rules/logging"
	_ "github.com/turenlabs/batou/internal/rules/memory"
	_ "github.com/turenlabs/batou/internal/rules/secrets"
	_ "github.com/turenlabs/batou/internal/rules/ssrf"
	_ "github.com/turenlabs/batou/internal/rules/traversal"
	_ "github.com/turenlabs/batou/internal/rules/validation"
	_ "github.com/turenlabs/batou/internal/rules/xss"
	_ "github.com/turenlabs/batou/internal/taint"
	_ "github.com/turenlabs/batou/internal/taint/goflow"
	_ "github.com/turenlabs/batou/internal/taint/languages"
)
