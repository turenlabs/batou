package framework

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Phoenix (Elixir) framework security rule patterns
// ---------------------------------------------------------------------------

var (
	// GTSS-FW-PHOENIX-001: raw/2 rendering unescaped user input
	rePhoenixRaw       = regexp.MustCompile(`\braw\s*\(`)
	rePhoenixRawPipe   = regexp.MustCompile(`\|>\s*raw\b`)

	// GTSS-FW-PHOENIX-002: Ecto raw SQL with string interpolation
	rePhoenixEctoFragment = regexp.MustCompile(`fragment\s*\(\s*"[^"]*#\{`)
	rePhoenixEctoRawSQL   = regexp.MustCompile(`Ecto\.Adapters\.SQL\.query[!]?\s*\(\s*\w+\s*,\s*"[^"]*#\{`)
	rePhoenixRepoQuery    = regexp.MustCompile(`Repo\.query[!]?\s*\(\s*"[^"]*#\{`)

	// GTSS-FW-PHOENIX-003: CSRF protection disabled
	rePhoenixCSRFDisable   = regexp.MustCompile(`(?:protect_from_forgery|:put_csrf_token).*false`)
	rePhoenixDeleteCSRF    = regexp.MustCompile(`delete_csrf_token\s*\(`)
	rePhoenixPlugCSRF      = regexp.MustCompile(`plug\s+:protect_from_forgery`)

	// GTSS-FW-PHOENIX-004: secret_key_base hardcoded
	rePhoenixSecretKey     = regexp.MustCompile(`secret_key_base\s*:\s*"[A-Za-z0-9+/=]{20,}"`)
	rePhoenixSecretKeyBase = regexp.MustCompile(`secret_key_base\s*[=:]\s*"[^"]{20,}"`)

	// GTSS-FW-PHOENIX-005: LiveView handle_event without authorization
	rePhoenixHandleEvent = regexp.MustCompile(`def\s+handle_event\s*\(`)

	// GTSS-FW-PHOENIX-006: Plug/router without auth pipeline
	rePhoenixPipeline    = regexp.MustCompile(`pipeline\s+:(?:api|browser)\s+do`)
	rePhoenixPlugAuth    = regexp.MustCompile(`plug\s+:(?:require_auth|ensure_auth|authenticate|verify_user|check_auth|require_login)`)
)

func init() {
	rules.Register(&PhoenixRaw{})
	rules.Register(&PhoenixEctoSQLi{})
	rules.Register(&PhoenixCSRFDisabled{})
	rules.Register(&PhoenixHardcodedSecret{})
	rules.Register(&PhoenixLiveViewAuth{})
	rules.Register(&PhoenixRouterNoAuth{})
}

// ---------------------------------------------------------------------------
// GTSS-FW-PHOENIX-001: raw/2 rendering unescaped user input
// ---------------------------------------------------------------------------

type PhoenixRaw struct{}

func (r *PhoenixRaw) ID() string                      { return "GTSS-FW-PHOENIX-001" }
func (r *PhoenixRaw) Name() string                    { return "PhoenixRaw" }
func (r *PhoenixRaw) DefaultSeverity() rules.Severity { return rules.High }
func (r *PhoenixRaw) Description() string {
	return "Detects Phoenix raw/2 function which renders unescaped HTML, potentially enabling XSS if used with user input."
}
func (r *PhoenixRaw) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PhoenixRaw) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Only scan Elixir-like files
	if !strings.HasSuffix(ctx.FilePath, ".ex") && !strings.HasSuffix(ctx.FilePath, ".exs") &&
		!strings.HasSuffix(ctx.FilePath, ".heex") && !strings.HasSuffix(ctx.FilePath, ".eex") &&
		!strings.HasSuffix(ctx.FilePath, ".leex") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		var matched string
		if m := rePhoenixRaw.FindString(line); m != "" {
			matched = m
		} else if m := rePhoenixRawPipe.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Phoenix raw/2 renders unescaped HTML (XSS risk)",
				Description:   "The raw/2 function in Phoenix marks content as safe HTML, bypassing automatic escaping in EEx/HEEx templates. If the content includes user input, this creates an XSS vulnerability.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Avoid raw/2 with user input. Use Phoenix's automatic HTML escaping (the default with <%= %>). If raw HTML is necessary, sanitize with HtmlSanitizeEx or a similar library first.",
				CWEID:         "CWE-79",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "phoenix", "elixir", "xss"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-PHOENIX-002: Ecto raw SQL with string interpolation
// ---------------------------------------------------------------------------

type PhoenixEctoSQLi struct{}

func (r *PhoenixEctoSQLi) ID() string                      { return "GTSS-FW-PHOENIX-002" }
func (r *PhoenixEctoSQLi) Name() string                    { return "PhoenixEctoSQLi" }
func (r *PhoenixEctoSQLi) DefaultSeverity() rules.Severity { return rules.High }
func (r *PhoenixEctoSQLi) Description() string {
	return "Detects Ecto fragment/query with string interpolation instead of parameterized queries, enabling SQL injection."
}
func (r *PhoenixEctoSQLi) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PhoenixEctoSQLi) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.HasSuffix(ctx.FilePath, ".ex") && !strings.HasSuffix(ctx.FilePath, ".exs") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		var matched string
		var title string
		if m := rePhoenixEctoFragment.FindString(line); m != "" {
			matched = m
			title = "Ecto fragment() with string interpolation (SQL injection)"
		} else if m := rePhoenixEctoRawSQL.FindString(line); m != "" {
			matched = m
			title = "Ecto.Adapters.SQL.query with string interpolation (SQL injection)"
		} else if m := rePhoenixRepoQuery.FindString(line); m != "" {
			matched = m
			title = "Repo.query with string interpolation (SQL injection)"
		}

		if matched != "" {
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         title,
				Description:   "An Ecto query uses Elixir string interpolation (#{}), which embeds values directly into the SQL string. This bypasses Ecto's parameterized query protection and enables SQL injection.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use Ecto's parameterized queries: fragment(\"column = ?\", ^value) or Repo.query(\"SELECT ... WHERE id = $1\", [value]). Never interpolate user input into SQL strings.",
				CWEID:         "CWE-89",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "phoenix", "elixir", "ecto", "sql-injection"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-PHOENIX-003: CSRF protection disabled
// ---------------------------------------------------------------------------

type PhoenixCSRFDisabled struct{}

func (r *PhoenixCSRFDisabled) ID() string                      { return "GTSS-FW-PHOENIX-003" }
func (r *PhoenixCSRFDisabled) Name() string                    { return "PhoenixCSRFDisabled" }
func (r *PhoenixCSRFDisabled) DefaultSeverity() rules.Severity { return rules.High }
func (r *PhoenixCSRFDisabled) Description() string {
	return "Detects Phoenix applications with CSRF protection disabled or CSRF tokens being deleted."
}
func (r *PhoenixCSRFDisabled) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PhoenixCSRFDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.HasSuffix(ctx.FilePath, ".ex") && !strings.HasSuffix(ctx.FilePath, ".exs") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		if m := rePhoenixCSRFDisable.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Phoenix CSRF protection disabled",
				Description:   "CSRF protection is explicitly disabled, allowing attackers to forge requests from other sites using authenticated user sessions.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Keep CSRF protection enabled by including plug :protect_from_forgery in your browser pipeline. For API endpoints using token auth, CSRF may not be needed but session-based routes must have it.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "phoenix", "elixir", "csrf"},
			})
		}

		if m := rePhoenixDeleteCSRF.FindString(line); m != "" {
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Phoenix CSRF token deleted",
				Description:   "delete_csrf_token() removes the CSRF token, disabling protection for subsequent requests. This weakens defense against cross-site request forgery attacks.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove the delete_csrf_token() call. If it is needed for a specific flow (e.g., after sign-out), ensure it only runs in that context.",
				CWEID:         "CWE-352",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "phoenix", "elixir", "csrf"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-PHOENIX-004: secret_key_base hardcoded
// ---------------------------------------------------------------------------

type PhoenixHardcodedSecret struct{}

func (r *PhoenixHardcodedSecret) ID() string                      { return "GTSS-FW-PHOENIX-004" }
func (r *PhoenixHardcodedSecret) Name() string                    { return "PhoenixHardcodedSecret" }
func (r *PhoenixHardcodedSecret) DefaultSeverity() rules.Severity { return rules.High }
func (r *PhoenixHardcodedSecret) Description() string {
	return "Detects hardcoded secret_key_base in Phoenix configuration, which compromises session signing and encryption."
}
func (r *PhoenixHardcodedSecret) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PhoenixHardcodedSecret) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.HasSuffix(ctx.FilePath, ".ex") && !strings.HasSuffix(ctx.FilePath, ".exs") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		var matched string
		if m := rePhoenixSecretKey.FindString(line); m != "" {
			matched = m
		} else if m := rePhoenixSecretKeyBase.FindString(line); m != "" {
			matched = m
		}

		if matched != "" {
			// Skip if it references System.get_env or an env variable
			if strings.Contains(line, "System.get_env") || strings.Contains(line, "${") {
				continue
			}
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Phoenix secret_key_base hardcoded",
				Description:   "The secret_key_base is hardcoded in the configuration file. This secret is used to sign and encrypt sessions, tokens, and cookies. If committed to source control, anyone with access can forge sessions and impersonate users.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use an environment variable: secret_key_base: System.get_env(\"SECRET_KEY_BASE\"). Generate a strong key with: mix phx.gen.secret",
				CWEID:         "CWE-798",
				OWASPCategory: "A07:2021-Identification and Authentication Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"framework", "phoenix", "elixir", "secrets"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-PHOENIX-005: LiveView handle_event without authorization
// ---------------------------------------------------------------------------

type PhoenixLiveViewAuth struct{}

func (r *PhoenixLiveViewAuth) ID() string                      { return "GTSS-FW-PHOENIX-005" }
func (r *PhoenixLiveViewAuth) Name() string                    { return "PhoenixLiveViewAuth" }
func (r *PhoenixLiveViewAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PhoenixLiveViewAuth) Description() string {
	return "Detects Phoenix LiveView handle_event callbacks without authorization checks, which may allow unauthorized actions."
}
func (r *PhoenixLiveViewAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PhoenixLiveViewAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.HasSuffix(ctx.FilePath, ".ex") && !strings.HasSuffix(ctx.FilePath, ".exs") {
		return nil
	}
	// Skip files that have authorization checks
	lower := strings.ToLower(ctx.Content)
	if strings.Contains(lower, "authorize") || strings.Contains(lower, "current_user") ||
		strings.Contains(lower, "require_auth") || strings.Contains(lower, "policy") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if rePhoenixHandleEvent.MatchString(line) {
			matched := t
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Phoenix LiveView handle_event without authorization",
				Description:   "A LiveView handle_event callback does not appear to check authorization. LiveView events can be triggered by any connected client, so each event handler should verify the user has permission to perform the action.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Add authorization checks in handle_event: verify socket.assigns.current_user has permission. Use on_mount hooks to authenticate the LiveView connection.",
				CWEID:         "CWE-862",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "phoenix", "elixir", "liveview", "authorization"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-FW-PHOENIX-006: Router without authentication pipeline
// ---------------------------------------------------------------------------

type PhoenixRouterNoAuth struct{}

func (r *PhoenixRouterNoAuth) ID() string                      { return "GTSS-FW-PHOENIX-006" }
func (r *PhoenixRouterNoAuth) Name() string                    { return "PhoenixRouterNoAuth" }
func (r *PhoenixRouterNoAuth) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *PhoenixRouterNoAuth) Description() string {
	return "Detects Phoenix router pipelines without authentication plugs, which may serve unprotected routes."
}
func (r *PhoenixRouterNoAuth) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PhoenixRouterNoAuth) Scan(ctx *rules.ScanContext) []rules.Finding {
	if !strings.HasSuffix(ctx.FilePath, ".ex") {
		return nil
	}
	// Only check router files
	if !strings.Contains(ctx.FilePath, "router") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inPipeline := false
	pipelineLine := 0
	pipelineName := ""
	hasAuth := false
	braceEnd := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		if rePhoenixPipeline.MatchString(line) {
			inPipeline = true
			pipelineLine = i
			hasAuth = false
			if strings.Contains(line, ":api") {
				pipelineName = ":api"
			} else {
				pipelineName = ":browser"
			}
			braceEnd = 0
			continue
		}

		if inPipeline {
			if rePhoenixPlugAuth.MatchString(line) || strings.Contains(line, "authenticate") || strings.Contains(line, "require_auth") {
				hasAuth = true
			}
			if strings.TrimSpace(line) == "end" {
				braceEnd = i
				inPipeline = false
				if !hasAuth {
					matched := strings.TrimSpace(lines[pipelineLine])
					if len(matched) > 120 {
						matched = matched[:120] + "..."
					}
					_ = braceEnd
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "Phoenix " + pipelineName + " pipeline without authentication plug",
						Description:   "The Phoenix router pipeline does not include an authentication plug. Routes using this pipeline will be accessible without authentication.",
						FilePath:      ctx.FilePath,
						LineNumber:    pipelineLine + 1,
						MatchedText:   matched,
						Suggestion:    "Add an authentication plug to the pipeline: plug :require_authenticated_user. Create separate pipelines for public and authenticated routes.",
						CWEID:         "CWE-306",
						OWASPCategory: "A07:2021-Identification and Authentication Failures",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"framework", "phoenix", "elixir", "authentication", "router"},
					})
				}
			}
		}
	}
	return findings
}
