package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Rails extended security rule patterns (RAILS-007 through RAILS-012)
// ---------------------------------------------------------------------------

var (
	// BATOU-FW-RAILS-007: protect_from_forgery missing in ApplicationController
	reRailsExtAppController    = regexp.MustCompile(`class\s+ApplicationController\s*<\s*ActionController::Base`)
	reRailsExtProtectForgery   = regexp.MustCompile(`protect_from_forgery`)

	// BATOU-FW-RAILS-008: Mass assignment via params.permit!
	reRailsExtPermitBang       = regexp.MustCompile(`params\s*\.permit!`)

	// BATOU-FW-RAILS-009: send_file with user-controlled path
	reRailsExtSendFile         = regexp.MustCompile(`send_file\s*\(\s*(?:params\[|"[^"]*#\{params|request\.|File\.join\s*\([^)]*params)`)
	reRailsExtSendFileVar      = regexp.MustCompile(`send_file\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)

	// BATOU-FW-RAILS-010: config.force_ssl not enabled
	reRailsExtForceSSLFalse    = regexp.MustCompile(`config\.force_ssl\s*=\s*false`)

	// BATOU-FW-RAILS-011: secret_key_base hardcoded in secrets.yml
	reRailsExtSecretKeyBase    = regexp.MustCompile(`(?i)secret_key_base\s*:\s*[A-Za-z0-9]{30,}`)
	reRailsExtSecretKeyBaseStr = regexp.MustCompile(`(?i)secret_key_base\s*[=:]\s*["'][A-Za-z0-9+/=]{30,}["']`)

	// BATOU-FW-RAILS-012: Devise without lockable
	reRailsExtDevise           = regexp.MustCompile(`devise\s*:`)
	reRailsExtDeviseLockable   = regexp.MustCompile(`:lockable`)
)

func init() {
	rules.Register(&RailsNoCSRFProtection{})
	rules.Register(&RailsPermitBangExt{})
	rules.Register(&RailsSendFileTraversal{})
	rules.Register(&RailsForceSSLDisabled{})
	rules.Register(&RailsHardcodedSecretKey{})
	rules.Register(&RailsDeviseNoLockable{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-007: protect_from_forgery not set in ApplicationController
// ---------------------------------------------------------------------------

type RailsNoCSRFProtection struct{}

func (r *RailsNoCSRFProtection) ID() string                      { return "BATOU-FW-RAILS-007" }
func (r *RailsNoCSRFProtection) Name() string                    { return "RailsNoCSRFProtection" }
func (r *RailsNoCSRFProtection) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsNoCSRFProtection) Description() string {
	return "Detects Rails ApplicationController inheriting from ActionController::Base without protect_from_forgery."
}
func (r *RailsNoCSRFProtection) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsNoCSRFProtection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reRailsExtAppController.MatchString(ctx.Content) {
		return nil
	}
	if reRailsExtProtectForgery.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reRailsExtAppController.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails ApplicationController without protect_from_forgery",
				Description:   "ApplicationController inherits from ActionController::Base but does not call protect_from_forgery. This means CSRF protection is disabled for all controllers, making the application vulnerable to cross-site request forgery attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add protect_from_forgery with: :exception to ApplicationController. For API-only controllers, use protect_from_forgery with: :null_session or use token-based authentication.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "rails", "csrf"},
			})
			break
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-008: Mass assignment via params.permit!
// ---------------------------------------------------------------------------

type RailsPermitBangExt struct{}

func (r *RailsPermitBangExt) ID() string                      { return "BATOU-FW-RAILS-008" }
func (r *RailsPermitBangExt) Name() string                    { return "RailsPermitBangExt" }
func (r *RailsPermitBangExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsPermitBangExt) Description() string {
	return "Detects Rails params.permit! which permits all parameters, bypassing strong parameter protection and enabling mass assignment."
}
func (r *RailsPermitBangExt) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsPermitBangExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reRailsExtPermitBang.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails params.permit! bypasses strong parameters (mass assignment)",
				Description:   "params.permit! permits all request parameters without filtering. An attacker can set any model attribute, including admin flags (is_admin), roles, foreign keys, or other privileged fields.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use explicit parameter whitelisting: params.require(:model).permit(:name, :email, :description). Only permit the specific fields that should be user-modifiable.",
				CWEID:         "CWE-915",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "rails", "mass-assignment", "strong-params"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-009: send_file with user-controlled path
// ---------------------------------------------------------------------------

type RailsSendFileTraversal struct{}

func (r *RailsSendFileTraversal) ID() string                      { return "BATOU-FW-RAILS-009" }
func (r *RailsSendFileTraversal) Name() string                    { return "RailsSendFileTraversal" }
func (r *RailsSendFileTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsSendFileTraversal) Description() string {
	return "Detects Rails send_file with user-controlled paths from params, which can lead to arbitrary file download via path traversal."
}
func (r *RailsSendFileTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsSendFileTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	hasParams := strings.Contains(ctx.Content, "params[") || strings.Contains(ctx.Content, "params.") ||
		strings.Contains(ctx.Content, "request.")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		if m := reRailsExtSendFile.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails send_file with user-controlled path (path traversal)",
				Description:   "send_file is called with a path derived from user input (params). An attacker can use path traversal sequences (../../) to download arbitrary files from the server, including /etc/passwd, database config, or source code.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Validate the file path: use File.expand_path and verify it's within an allowed directory. Use send_file with an absolute base path and sanitize filenames: File.basename(params[:filename]).",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "rails", "path-traversal", "file-download"},
			})
		} else if hasParams && reRailsExtSendFileVar.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails send_file with variable path in params-handling controller",
				Description:   "send_file is called with a variable in a controller that handles user params. If the variable is derived from user input, this enables arbitrary file download.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Ensure the file path is not derived from user input. Use File.expand_path and verify it's within an allowed directory. Use an ID-to-path mapping instead of user-supplied filenames.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "rails", "path-traversal", "file-download"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-010: config.force_ssl not enabled
// ---------------------------------------------------------------------------

type RailsForceSSLDisabled struct{}

func (r *RailsForceSSLDisabled) ID() string                      { return "BATOU-FW-RAILS-010" }
func (r *RailsForceSSLDisabled) Name() string                    { return "RailsForceSSLDisabled" }
func (r *RailsForceSSLDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RailsForceSSLDisabled) Description() string {
	return "Detects Rails config.force_ssl explicitly set to false, allowing unencrypted HTTP connections."
}
func (r *RailsForceSSLDisabled) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsForceSSLDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reRailsExtForceSSLFalse.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails force_ssl disabled",
				Description:   "config.force_ssl = false allows HTTP connections, exposing session cookies, credentials, and user data to network interception. Rails' force_ssl also sets HSTS headers and marks cookies as Secure.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Set config.force_ssl = true in production.rb. This forces HTTPS, sets HSTS headers, and marks cookies as Secure.",
				CWEID:         "CWE-319",
				OWASPCategory: "A02:2021-Cryptographic Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "rails", "ssl", "transport-security"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-011: secret_key_base hardcoded
// ---------------------------------------------------------------------------

type RailsHardcodedSecretKey struct{}

func (r *RailsHardcodedSecretKey) ID() string                      { return "BATOU-FW-RAILS-011" }
func (r *RailsHardcodedSecretKey) Name() string                    { return "RailsHardcodedSecretKey" }
func (r *RailsHardcodedSecretKey) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsHardcodedSecretKey) Description() string {
	return "Detects hardcoded secret_key_base in Rails secrets.yml or credentials, which compromises session signing and encryption."
}
func (r *RailsHardcodedSecretKey) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby, rules.LangAny}
}

func (r *RailsHardcodedSecretKey) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		var matched string
		if m := reRailsExtSecretKeyBase.FindString(line); m != "" {
			matched = m
		} else if m := reRailsExtSecretKeyBaseStr.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			// Skip if it references ERB or env variable
			if strings.Contains(line, "<%=") || strings.Contains(line, "ENV[") || strings.Contains(line, "ENV.fetch") {
				continue
			}
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails secret_key_base hardcoded",
				Description:   "The secret_key_base is hardcoded in a configuration file. This secret is used to sign and verify session cookies, CSRF tokens, and encrypted credentials. If committed to source control, an attacker can forge sessions and decrypt credentials.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use environment variables: secret_key_base: <%= ENV['SECRET_KEY_BASE'] %>. Or use Rails encrypted credentials: rails credentials:edit. Generate a new key: rails secret.",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "rails", "secrets", "secret-key"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-012: Devise without lockable (brute force)
// ---------------------------------------------------------------------------

type RailsDeviseNoLockable struct{}

func (r *RailsDeviseNoLockable) ID() string                      { return "BATOU-FW-RAILS-012" }
func (r *RailsDeviseNoLockable) Name() string                    { return "RailsDeviseNoLockable" }
func (r *RailsDeviseNoLockable) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RailsDeviseNoLockable) Description() string {
	return "Detects Rails Devise model configuration without the :lockable module, which means no protection against brute-force login attacks."
}
func (r *RailsDeviseNoLockable) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsDeviseNoLockable) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !reRailsExtDevise.MatchString(ctx.Content) {
		return nil
	}
	if reRailsExtDeviseLockable.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if reRailsExtDevise.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Rails Devise without :lockable module (brute-force risk)",
				Description:   "The Devise configuration does not include the :lockable module. Without account lockout, attackers can perform unlimited login attempts via brute-force or credential stuffing attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add :lockable to the devise declaration: devise :database_authenticatable, :lockable, ... Also add lock_strategy and unlock_strategy to the Devise initializer.",
				CWEID:         "CWE-307",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "rails", "devise", "brute-force", "authentication"},
			})
			break
		}
	}
	return findings
}
