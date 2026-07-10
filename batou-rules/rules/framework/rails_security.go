package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// Rails security AST/config rules (RAILS-014 through RAILS-019)
//
// These detect framework-anchored misconfigurations and unsafe-by-shape helper
// calls that are not taint flows: a format validator with the wrong regex
// anchors, a reverse-tabnabbing link, a verb-permissive route, JSON entity
// escaping turned off, mass-assignment protection globally disabled, and a
// dynamic render path. Each fires only on the precise dangerous shape so safe
// usage stays clean.
// ---------------------------------------------------------------------------

var (
	// RAILS-014: validates ... format: /.../ using ^...$ (per-line) instead of
	// \A...\z (whole-string). Ruby's ^ and $ match at newline boundaries, so a
	// payload like "ok\n<script>" passes a `/^ok$/` validator — multiline
	// validation bypass (CWE-625). We require the validates call to carry a
	// :format option with a regexp literal, then flag when that literal uses
	// ^/$ and lacks \A/\z.
	reRailsValidatesFormat = regexp.MustCompile(`\bvalidates(?:_format_of)?\b.*\bformat\s*:\s*(?:\{[^}]*with\s*:\s*)?/`)
	reRailsFormatWithRegex = regexp.MustCompile(`\bwith\s*:\s*/([^/]*)/`)
	reRailsFormatBareRegex = regexp.MustCompile(`\bformat\s*:\s*/([^/]*)/`)

	// RAILS-015: link_to ... target: "_blank" without rel: noopener/noreferrer.
	reRailsLinkToBlank = regexp.MustCompile(`\blink_to\b`)
	reRailsTargetBlank = regexp.MustCompile(`target\s*:\s*["']_blank["']|["']target["']\s*=>\s*["']_blank["']`)
	reRailsRelNoopener = regexp.MustCompile(`(?i)rel\s*:\s*["'][^"']*noopener|(?i)rel\s*:\s*["'][^"']*noreferrer|(?i)["']rel["']\s*=>\s*["'][^"']*noopener`)

	// RAILS-016: http_basic_authenticate_with with literal name:/password:.
	reRailsHTTPBasicAuth = regexp.MustCompile(`\bhttp_basic_authenticate_with\b`)
	reRailsHTTPBasicLit  = regexp.MustCompile(`(?:name|password)\s*:\s*["'][^"']+["']`)
	reRailsHTTPBasicEnv  = regexp.MustCompile(`ENV\b|Rails\.application\.credentials|credentials\.`)

	// RAILS-017: verb-permissive route. `match '...', via: :all` (in either the
	// `via: :all` or hash-rocket `:via => :all` syntax) maps every HTTP verb to
	// one action — GET can then trigger a state change (CWE-650). `via: :all` is
	// an unambiguous, high-signal token, so we flag it wherever it appears in a
	// routes file (it may sit on a continuation line of a multi-line match).
	reRailsRouteViaAll = regexp.MustCompile(`(?:\bvia\s*:\s*:all\b|:via\s*=>\s*:all\b)`)

	// RAILS-018: ActiveSupport.escape_html_entities_in_json = false disables
	// JSON entity escaping globally — render json: with user data can break out
	// of a <script> JSON island (CWE-79).
	reRailsJSONEscapeOff = regexp.MustCompile(`escape_html_entities_in_json\s*=\s*false`)

	// RAILS-019: mass-assignment protection globally disabled.
	reRailsWhitelistOff = regexp.MustCompile(`whitelist_attributes\s*=\s*false`)
)

func init() {
	rules.Register(&RailsCalcSQLi{})
	rules.Register(&RailsValidatesAnchors{})
	rules.Register(&RailsLinkToTabnab{})
	rules.Register(&RailsHTTPBasicHardcoded{})
	rules.Register(&RailsVerbPermissiveRoute{})
	rules.Register(&RailsJSONEscapeDisabled{})
	rules.Register(&RailsWhitelistAttributesOff{})
	rules.Register(&RailsDynamicRender{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-014: validates :format with ^...$ instead of \A...\z
// ---------------------------------------------------------------------------

type RailsValidatesAnchors struct{}

func (r *RailsValidatesAnchors) ID() string                      { return "BATOU-FW-RAILS-014" }
func (r *RailsValidatesAnchors) Name() string                    { return "RailsValidatesAnchors" }
func (r *RailsValidatesAnchors) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsValidatesAnchors) Description() string {
	return "Detects ActiveModel validates :format regexes that use ^...$ anchors instead of \\A...\\z, allowing newline-smuggled payloads to bypass validation."
}
func (r *RailsValidatesAnchors) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsValidatesAnchors) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRailsValidatesFormat, line, lowered[i]) {
			continue
		}
		// Extract the regex body (prefer the `with:` form, fall back to bare `format:`).
		var body string
		if m := rules.GFindSubmatchLower(reRailsFormatWithRegex, line, lowered[i]); m != nil {
			body = m[1]
		} else if m := rules.GFindSubmatchLower(reRailsFormatBareRegex, line, lowered[i]); m != nil {
			body = m[1]
		} else {
			continue
		}
		// Dangerous only when the regex uses ^ or $ as anchors AND does not use
		// the safe whole-string anchors \A / \z (or \Z).
		usesLineAnchor := strings.Contains(body, "^") || strings.Contains(body, "$")
		usesStringAnchor := strings.Contains(body, `\A`) || strings.Contains(body, `\z`) || strings.Contains(body, `\Z`)
		if !usesLineAnchor || usesStringAnchor {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails validates :format with ^...$ line anchors (validation bypass)",
			Description:   "In Ruby regexes, ^ and $ match at line boundaries, not the start/end of the whole string. A format validator like /^[a-z]+$/ accepts \"safe\\n<script>alert(1)</script>\" because the malicious second line is on a different line. Attackers smuggle payloads (XSS, SQLi, header injection) past the validator using embedded newlines.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Anchor the whole string with \\A and \\z: validates :name, format: { with: /\\A[a-z]+\\z/ }. Never use ^...$ for input validation.",
			CWEID:         "CWE-625",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "validation", "regex-anchor", "bypass"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-015: link_to target: "_blank" without rel: noopener
// ---------------------------------------------------------------------------

type RailsLinkToTabnab struct{}

func (r *RailsLinkToTabnab) ID() string                      { return "BATOU-FW-RAILS-015" }
func (r *RailsLinkToTabnab) Name() string                    { return "RailsLinkToTabnab" }
func (r *RailsLinkToTabnab) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RailsLinkToTabnab) Description() string {
	return "Detects Rails link_to with target: '_blank' but no rel: 'noopener'/'noreferrer', exposing the app to reverse tabnabbing."
}
func (r *RailsLinkToTabnab) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsLinkToTabnab) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRailsLinkToBlank, line, lowered[i]) || !rules.GMatchLower(reRailsTargetBlank, line, lowered[i]) {
			continue
		}
		if rules.GMatchLower(reRailsRelNoopener, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails link_to target: '_blank' without rel: noopener (reverse tabnabbing)",
			Description:   "A link opened with target: '_blank' gives the destination page a window.opener reference back to your page. Without rel: 'noopener', the opened page can rewrite window.opener.location to a phishing site (reverse tabnabbing).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Add rel: 'noopener noreferrer': link_to 'X', url, target: '_blank', rel: 'noopener noreferrer'.",
			CWEID:         "CWE-1022",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "tabnabbing", "link_to", "noopener"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-016: http_basic_authenticate_with hardcoded credentials
// ---------------------------------------------------------------------------

type RailsHTTPBasicHardcoded struct{}

func (r *RailsHTTPBasicHardcoded) ID() string                      { return "BATOU-FW-RAILS-016" }
func (r *RailsHTTPBasicHardcoded) Name() string                    { return "RailsHTTPBasicHardcoded" }
func (r *RailsHTTPBasicHardcoded) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsHTTPBasicHardcoded) Description() string {
	return "Detects http_basic_authenticate_with with literal name:/password: strings, hardcoding HTTP Basic credentials in source."
}
func (r *RailsHTTPBasicHardcoded) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsHTTPBasicHardcoded) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRailsHTTPBasicAuth, line, lowered[i]) {
			continue
		}
		if !rules.GMatchLower(reRailsHTTPBasicLit, line, lowered[i]) {
			continue
		}
		// If the literal is sourced from ENV/credentials, it's not hardcoded.
		if rules.GMatchLower(reRailsHTTPBasicEnv, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails http_basic_authenticate_with hardcoded credentials",
			Description:   "http_basic_authenticate_with carries a literal name: or password: string. These credentials are committed to source control, are identical across every deployment, and cannot be rotated without a code change.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Load credentials from the environment or Rails credentials: http_basic_authenticate_with name: ENV['ADMIN_USER'], password: ENV['ADMIN_PASS'].",
			CWEID:         "CWE-798",
			OWASPCategory: "A07:2021-Identification and Authentication Failures",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "hardcoded-credentials", "http-basic"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-017: verb-permissive route (match via: :all / no via)
// ---------------------------------------------------------------------------

type RailsVerbPermissiveRoute struct{}

func (r *RailsVerbPermissiveRoute) ID() string                      { return "BATOU-FW-RAILS-017" }
func (r *RailsVerbPermissiveRoute) Name() string                    { return "RailsVerbPermissiveRoute" }
func (r *RailsVerbPermissiveRoute) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RailsVerbPermissiveRoute) Description() string {
	return "Detects Rails routes that match all HTTP verbs (match ... via: :all), enabling GET-based state changes and CSRF via verb confusion."
}
func (r *RailsVerbPermissiveRoute) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsVerbPermissiveRoute) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	// Only meaningful in a routes file (routes.rb) or an explicit draw block.
	isRoutes := strings.Contains(ctx.FilePath, "routes") ||
		strings.Contains(ctx.Content, "Rails.application.routes.draw") ||
		strings.Contains(ctx.Content, ".routes.draw")
	if !isRoutes {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRailsRouteViaAll, line, lowered[i]) {
			continue
		}
		desc := "`match ..., via: :all` maps every HTTP verb to one action. A state-changing action is then reachable via GET, bypassing CSRF protection and enabling verb-confusion attacks."
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails verb-permissive route (match all HTTP verbs)",
			Description:   desc,
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Constrain the verb explicitly: use get/post/put/delete, or match '...', via: :post. Reserve match/via: :all for read-only endpoints only.",
			CWEID:         "CWE-650",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "medium",
			Tags:          []string{"rails", "routing", "csrf", "verb-confusion"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-018: escape_html_entities_in_json = false
// ---------------------------------------------------------------------------

type RailsJSONEscapeDisabled struct{}

func (r *RailsJSONEscapeDisabled) ID() string                      { return "BATOU-FW-RAILS-018" }
func (r *RailsJSONEscapeDisabled) Name() string                    { return "RailsJSONEscapeDisabled" }
func (r *RailsJSONEscapeDisabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RailsJSONEscapeDisabled) Description() string {
	return "Detects ActiveSupport.escape_html_entities_in_json = false, which disables HTML-entity escaping in JSON responses and can lead to XSS when JSON is embedded in HTML."
}
func (r *RailsJSONEscapeDisabled) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsJSONEscapeDisabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRailsJSONEscapeOff, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails JSON HTML-entity escaping disabled",
			Description:   "ActiveSupport.escape_html_entities_in_json = false stops Rails from escaping <, >, and & in JSON output. When that JSON is rendered inside an HTML <script> island (the common pattern for bootstrapping client state), an attacker-controlled value can break out with </script> and inject markup — stored/reflected XSS.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Leave escape_html_entities_in_json at its default (true). If JSON must be embedded in HTML, escape it at the output boundary with json_escape / j.",
			CWEID:         "CWE-79",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "xss", "json", "misconfiguration"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-019: config.active_record.whitelist_attributes = false
// ---------------------------------------------------------------------------

type RailsWhitelistAttributesOff struct{}

func (r *RailsWhitelistAttributesOff) ID() string                      { return "BATOU-FW-RAILS-019" }
func (r *RailsWhitelistAttributesOff) Name() string                    { return "RailsWhitelistAttributesOff" }
func (r *RailsWhitelistAttributesOff) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsWhitelistAttributesOff) Description() string {
	return "Detects config.active_record.whitelist_attributes = false, which globally disables mass-assignment protection (legacy Rails 3)."
}
func (r *RailsWhitelistAttributesOff) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsWhitelistAttributesOff) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		if !rules.GMatchLower(reRailsWhitelistOff, line, lowered[i]) {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails mass-assignment protection globally disabled",
			Description:   "whitelist_attributes = false turns off attr_accessible enforcement for every model. Any request parameter can then set any attribute (admin flags, roles, foreign keys), enabling mass-assignment privilege escalation across the whole app.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Remove this line (default is true on Rails 3) and migrate to strong parameters (params.require(:m).permit(...)).",
			CWEID:         "CWE-915",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "mass-assignment", "misconfiguration"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-RAILS-020: dynamic render path (LFI / partial include)
//
// `render params[:template]`, `render "reports/#{params[:id]}"`, or a bare
// `render some_var` where the controller handles params, selects the template
// from user input. ActionView resolves the path against the view roots, so an
// attacker can include arbitrary partials/templates (path traversal / LFI),
// distinct from the already-covered render inline:/file:/html:.
// ---------------------------------------------------------------------------

var (
	// render params[:x]  /  render(params[:x])
	reRailsRenderParams = regexp.MustCompile(`\brender\s*\(?\s*params\s*\[`)
	// render "dir/#{...}" — interpolated string template path (no keyword option)
	reRailsRenderInterp = regexp.MustCompile(`\brender\s*\(?\s*"[^"]*#\{`)
	// Lines that are a *keyword* render (render json:, render inline:, render
	// file:, render html:, render partial:, render template:, render plain:,
	// render status:, render layout:) are handled elsewhere or are safe — skip.
	reRailsRenderKeyword = regexp.MustCompile(`\brender\s*\(?\s*(?:json|inline|file|html|plain|text|xml|js|nothing|status|layout|content_type|location|body|action)\s*:`)
)

type RailsDynamicRender struct{}

func (r *RailsDynamicRender) ID() string                      { return "BATOU-FW-RAILS-020" }
func (r *RailsDynamicRender) Name() string                    { return "RailsDynamicRender" }
func (r *RailsDynamicRender) DefaultSeverity() rules.Severity { return rules.High }
func (r *RailsDynamicRender) Description() string {
	return "Detects Rails render with a user-derived template/partial path (render params[:t] or render \"dir/#{...}\"), enabling local file inclusion / arbitrary partial rendering."
}
func (r *RailsDynamicRender) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RailsDynamicRender) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangRuby {
		return nil
	}
	var findings []rules.Finding
	lines := ctx.SplitLines()
	lowered := ctx.LowerLines()
	for i, line := range lines {
		if isComment(line) {
			continue
		}
		// Keyword-option renders are not dynamic-path renders.
		if rules.GMatchLower(reRailsRenderKeyword, line, lowered[i]) {
			continue
		}
		var dyn bool
		if rules.GMatchLower(reRailsRenderParams, line, lowered[i]) {
			dyn = true
		} else if rules.GMatchLower(reRailsRenderInterp, line, lowered[i]) {
			// Only treat the interpolated string as user-derived when the line
			// (or interpolation) references a request source — keeps static
			// partial paths like render "shared/#{type}" with a local symbol
			// from flooding. Require params/request/cookies presence.
			if strings.Contains(line, "params") || strings.Contains(line, "request") || strings.Contains(line, "cookies") {
				dyn = true
			}
		}
		if !dyn {
			continue
		}
		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Rails render with user-derived template path (LFI)",
			Description:   "render's first positional argument selects a template/partial by path. When that path comes from params or an interpolated request value, an attacker can traverse to and render arbitrary templates/partials in the view roots, leaking their contents or triggering unintended view logic (local file inclusion).",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   truncate(strings.TrimSpace(line), 120),
			Suggestion:    "Map user input to a fixed allowlist of template names before rendering: TEMPLATES.fetch(params[:view]) { 'default' }. Never pass params directly to render.",
			CWEID:         "CWE-22",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"rails", "lfi", "path-traversal", "render"},
		})
	}
	return findings
}
