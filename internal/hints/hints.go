// Package hints generates actionable security guidance for Claude Code.
//
// Unlike traditional scanner output that just reports findings, hints are
// designed as a real-time feedback loop: every time Claude writes code,
// GTSS feeds back specific, contextual advice that helps Claude improve
// the code immediately.
//
// Hints include:
//   - The complete taint path (source → var1 → var2 → sink)
//   - Concrete code fix examples in the target language
//   - Affected callers from the call graph (interprocedural impact)
//   - Architectural suggestions when vulnerability patterns repeat
//   - Priority ordering so Claude fixes the worst issues first
//   - Positive reinforcement when code is clean
package hints

import (
	"fmt"
	"strings"
	"time"

	"github.com/turen/gtss/internal/graph"
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

// HintContext contains everything needed to generate hints for a scan.
type HintContext struct {
	FilePath   string
	Language   rules.Language
	Findings   []rules.Finding
	TaintFlows []taint.TaintFlow
	CallGraph  *graph.CallGraph
	ChangedFunc string    // The function that was just modified
	IsNewFile  bool       // True if this is a new file (Write), false for Edit
	ScanTimeMs int64
}

// Hint represents a single piece of actionable advice for Claude.
type Hint struct {
	Priority    int            // 1 = most urgent
	Severity    rules.Severity // Matches the finding severity
	Category    string         // e.g., "taint_flow", "pattern", "architecture", "positive"
	Title       string         // Short summary
	Explanation string         // Why this matters
	FixExample  string         // Concrete code showing the fix
	Impact      string         // What happens if this isn't fixed
	References  []string       // CWE, OWASP links
	AffectedBy  []string       // Other functions impacted (from call graph)
}

// GenerateHints produces actionable hints from scan results.
func GenerateHints(ctx *HintContext) []Hint {
	var hints []Hint

	// Generate hints from taint flows (highest value)
	for _, flow := range ctx.TaintFlows {
		h := hintFromTaintFlow(flow, ctx)
		hints = append(hints, h)
	}

	// Generate hints from regex findings not already covered by taint flows
	covered := make(map[int]bool)
	for _, flow := range ctx.TaintFlows {
		covered[flow.SinkLine] = true
	}
	for _, f := range ctx.Findings {
		if !covered[f.LineNumber] {
			h := hintFromFinding(f, ctx)
			hints = append(hints, h)
		}
	}

	// Generate interprocedural impact hints
	if ctx.CallGraph != nil && ctx.ChangedFunc != "" {
		impactHints := hintFromCallGraph(ctx)
		hints = append(hints, impactHints...)
	}

	// Generate architectural hints if patterns repeat
	archHints := detectPatterns(ctx)
	hints = append(hints, archHints...)

	// Sort by priority (severity descending, then by category)
	sortHints(hints)

	// Always add a summary hint
	if len(hints) == 0 {
		hints = append(hints, positiveHint(ctx))
	}

	return hints
}

// FormatForClaude renders all hints into the additionalContext string
// that gets fed back to Claude Code.
func FormatForClaude(ctx *HintContext, hints []Hint) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("\n=== GTSS Security Copilot [%s] ===\n", ctx.FilePath))
	b.WriteString(fmt.Sprintf("Language: %s | Scan: %dms", ctx.Language, ctx.ScanTimeMs))
	if ctx.CallGraph != nil {
		stats := ctx.CallGraph.Stats()
		b.WriteString(fmt.Sprintf(" | Graph: %d funcs, %d edges", stats.TotalFunctions, stats.TotalEdges))
	}
	b.WriteString("\n\n")

	if len(hints) == 0 || (len(hints) == 1 && hints[0].Category == "positive") {
		b.WriteString("No security issues detected. Code looks clean.\n")
		if len(hints) == 1 {
			b.WriteString(hints[0].Explanation)
			b.WriteString("\n")
		}
		b.WriteString("=== End GTSS ===\n")
		return b.String()
	}

	// Count by severity
	sevCounts := make(map[rules.Severity]int)
	for _, h := range hints {
		if h.Category != "positive" {
			sevCounts[h.Severity]++
		}
	}
	parts := []string{}
	for _, sev := range []rules.Severity{rules.Critical, rules.High, rules.Medium, rules.Low} {
		if c := sevCounts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", sev, c))
		}
	}
	if len(parts) > 0 {
		b.WriteString(fmt.Sprintf("Issues: %s\n\n", strings.Join(parts, " | ")))
	}

	for i, h := range hints {
		if h.Category == "positive" {
			continue
		}

		b.WriteString(fmt.Sprintf("--- Hint %d [%s] ---\n", i+1, h.Severity))
		b.WriteString(fmt.Sprintf("%s\n", h.Title))
		b.WriteString(fmt.Sprintf("\nWhy: %s\n", h.Explanation))

		if h.FixExample != "" {
			b.WriteString(fmt.Sprintf("\nFix:\n%s\n", h.FixExample))
		}

		if h.Impact != "" {
			b.WriteString(fmt.Sprintf("\nImpact: %s\n", h.Impact))
		}

		if len(h.AffectedBy) > 0 {
			b.WriteString(fmt.Sprintf("\nAlso affects: %s\n", strings.Join(h.AffectedBy, ", ")))
		}

		if len(h.References) > 0 {
			b.WriteString(fmt.Sprintf("Refs: %s\n", strings.Join(h.References, ", ")))
		}

		b.WriteString("\n")
	}

	b.WriteString("=== End GTSS ===\n")
	return b.String()
}

func hintFromTaintFlow(flow taint.TaintFlow, ctx *HintContext) Hint {
	// Build path visualization
	path := flow.Source.MethodName
	for _, step := range flow.Steps {
		path += " → " + step.VarName
	}
	path += " → " + flow.Sink.MethodName

	h := Hint{
		Priority: severityToPriority(flow.Sink.Severity),
		Severity: flow.Sink.Severity,
		Category: "taint_flow",
		Title: fmt.Sprintf("Tainted data flows from %s to %s (line %d → %d)",
			flow.Source.Category, flow.Sink.Category, flow.SourceLine, flow.SinkLine),
		Explanation: fmt.Sprintf(
			"User-controlled data enters via %s (line %d), flows through [%s], "+
				"and reaches %s (line %d) without sanitization.",
			flow.Source.Description, flow.SourceLine, path,
			flow.Sink.Description, flow.SinkLine),
		FixExample: generateFixExample(flow, ctx.Language),
		Impact: impactDescription(string(flow.Sink.Category)),
		References: []string{},
	}

	if flow.Sink.CWEID != "" {
		h.References = append(h.References, flow.Sink.CWEID)
	}
	if flow.Sink.OWASPCategory != "" {
		h.References = append(h.References, flow.Sink.OWASPCategory)
	}

	// Check call graph for impacted callers
	if ctx.CallGraph != nil {
		funcID := graph.FuncID(ctx.FilePath, flow.ScopeName)
		callers := ctx.CallGraph.GetTransitiveCallers(funcID, 3)
		for _, caller := range callers {
			h.AffectedBy = append(h.AffectedBy,
				fmt.Sprintf("%s (%s:%d)", caller.Name, caller.FilePath, caller.StartLine))
		}
	}

	return h
}

func hintFromFinding(f rules.Finding, ctx *HintContext) Hint {
	h := Hint{
		Priority:    severityToPriority(f.Severity),
		Severity:    f.Severity,
		Category:    "finding",
		Title:       fmt.Sprintf("[%s] %s (line %d)", f.RuleID, f.Title, f.LineNumber),
		Explanation: f.Description,
		Impact:      impactDescription(string(categorizeRule(f.RuleID))),
		References:  []string{},
	}

	if f.Suggestion != "" {
		h.FixExample = f.Suggestion
	}
	if f.CWEID != "" {
		h.References = append(h.References, f.CWEID)
	}
	if f.OWASPCategory != "" {
		h.References = append(h.References, f.OWASPCategory)
	}

	return h
}

func hintFromCallGraph(ctx *HintContext) []Hint {
	var hints []Hint

	funcID := graph.FuncID(ctx.FilePath, ctx.ChangedFunc)
	node := ctx.CallGraph.GetNode(funcID)
	if node == nil {
		return nil
	}

	callers := ctx.CallGraph.GetCallers(funcID)
	if len(callers) == 0 {
		return nil
	}

	// If the changed function has taint issues, warn about callers
	if len(node.TaintSig.SinkCalls) > 0 || len(node.TaintSig.TaintedReturns) > 0 {
		callerNames := make([]string, 0, len(callers))
		for _, c := range callers {
			callerNames = append(callerNames, fmt.Sprintf("%s (%s:%d)", c.Name, c.FilePath, c.StartLine))
		}

		hints = append(hints, Hint{
			Priority: 2,
			Severity: rules.High,
			Category: "interprocedural",
			Title: fmt.Sprintf("Function %s has %d callers that may be affected",
				ctx.ChangedFunc, len(callers)),
			Explanation: fmt.Sprintf(
				"Changes to %s affect its callers. If this function now returns tainted data "+
					"or has new security-sensitive behavior, callers should be reviewed.",
				ctx.ChangedFunc),
			AffectedBy: callerNames,
		})
	}

	return hints
}

func detectPatterns(ctx *HintContext) []Hint {
	var hints []Hint

	// Count finding categories
	cats := make(map[string]int)
	for _, f := range ctx.Findings {
		cats[categorizeRule(f.RuleID)]++
	}

	// If same category appears 3+ times, suggest architectural fix
	for cat, count := range cats {
		if count >= 3 {
			hints = append(hints, Hint{
				Priority:    3,
				Severity:    rules.Medium,
				Category:    "architecture",
				Title:       fmt.Sprintf("Recurring pattern: %d %s issues — consider an architectural fix", count, cat),
				Explanation: architecturalAdvice(cat),
			})
		}
	}

	return hints
}

func positiveHint(ctx *HintContext) Hint {
	return Hint{
		Priority: 99,
		Severity: rules.Info,
		Category: "positive",
		Title:    "Clean scan",
		Explanation: fmt.Sprintf("No security issues detected in %s. "+
			"Code follows secure patterns.", ctx.FilePath),
	}
}

// generateFixExample produces a language-specific code example for fixing
// a taint flow vulnerability.
func generateFixExample(flow taint.TaintFlow, lang rules.Language) string {
	cat := flow.Sink.Category

	switch cat {
	case taint.SnkSQLQuery:
		return sqlFixExample(lang)
	case taint.SnkCommand:
		return commandFixExample(lang)
	case taint.SnkHTMLOutput:
		return xssFixExample(lang)
	case taint.SnkFileWrite:
		return pathFixExample(lang)
	case taint.SnkRedirect:
		return redirectFixExample(lang)
	case taint.SnkEval:
		return evalFixExample(lang)
	case taint.SnkURLFetch:
		return ssrfFixExample(lang)
	case taint.SnkDeserialize:
		return deserializationFixExample(lang)
	default:
		return flow.Sink.Description
	}
}

func sqlFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Instead of:\n" +
			"  db.Query(\"SELECT * FROM users WHERE id = \" + userID)\n" +
			"  // Use parameterized queries:\n" +
			"  db.Query(\"SELECT * FROM users WHERE id = ?\", userID)"
	case rules.LangPython:
		return "  # Instead of:\n" +
			"  cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n" +
			"  # Use parameterized queries:\n" +
			"  cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Instead of:\n" +
			"  db.query(\"SELECT * FROM users WHERE id = \" + userId)\n" +
			"  // Use parameterized queries:\n" +
			"  db.query(\"SELECT * FROM users WHERE id = ?\", [userId])"
	case rules.LangJava:
		return "  // Instead of:\n" +
			"  stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + userId);\n" +
			"  // Use PreparedStatement:\n" +
			"  PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\");\n" +
			"  ps.setString(1, userId);\n" +
			"  ps.executeQuery();"
	case rules.LangPHP:
		return "  // Instead of:\n" +
			"  $stmt = $pdo->query(\"SELECT * FROM users WHERE id = \" . $id);\n" +
			"  // Use prepared statements:\n" +
			"  $stmt = $pdo->prepare(\"SELECT * FROM users WHERE id = ?\");\n" +
			"  $stmt->execute([$id]);"
	case rules.LangRuby:
		return "  # Instead of:\n" +
			"  User.where(\"id = #{params[:id]}\")\n" +
			"  # Use parameterized queries:\n" +
			"  User.where(id: params[:id])"
	default:
		return "  Use parameterized queries instead of string concatenation."
	}
}

func commandFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Instead of:\n" +
			"  exec.Command(\"sh\", \"-c\", userInput)\n" +
			"  // Use explicit command and args:\n" +
			"  exec.Command(\"ls\", \"-la\", sanitizedPath)"
	case rules.LangPython:
		return "  # Instead of:\n" +
			"  os.system(user_input)\n" +
			"  # Use subprocess with list args (no shell):\n" +
			"  subprocess.run([\"ls\", \"-la\", sanitized_path], shell=False)"
	default:
		return "  Avoid shell execution. Use explicit command and argument lists."
	}
}

func xssFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Use html/template (auto-escapes) or:\n" +
			"  safe := html.EscapeString(userInput)\n" +
			"  fmt.Fprintf(w, \"<p>%s</p>\", safe)"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Instead of:\n" +
			"  element.innerHTML = userInput\n" +
			"  // Use textContent (auto-escapes):\n" +
			"  element.textContent = userInput\n" +
			"  // Or use DOMPurify:\n" +
			"  element.innerHTML = DOMPurify.sanitize(userInput)"
	case rules.LangPython:
		return "  # Use template auto-escaping (Jinja2 default) or:\n" +
			"  from markupsafe import escape\n" +
			"  safe = escape(user_input)"
	default:
		return "  Escape output for the context (HTML, JS, URL, CSS)."
	}
}

func pathFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Validate path doesn't escape base directory:\n" +
			"  clean := filepath.Clean(userPath)\n" +
			"  full := filepath.Join(baseDir, clean)\n" +
			"  if !strings.HasPrefix(full, baseDir) {\n" +
			"      return errors.New(\"path traversal detected\")\n" +
			"  }"
	default:
		return "  Canonicalize the path and verify it stays within the allowed directory."
	}
}

func redirectFixExample(lang rules.Language) string {
	return "  // Validate redirect URL against an allowlist of trusted domains,\n" +
		"  // or only allow relative paths (no protocol)."
}

func evalFixExample(lang rules.Language) string {
	return "  // Never pass user input to eval/exec.\n" +
		"  // Use safe alternatives: JSON.parse(), ast.literal_eval(), etc."
}

func ssrfFixExample(lang rules.Language) string {
	return "  // Validate URLs against an allowlist of trusted hosts.\n" +
		"  // Block internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.169.254)."
}

func deserializationFixExample(lang rules.Language) string {
	return "  // Use safe formats (JSON) instead of language-native serialization.\n" +
		"  // If deserialization is required, use allowlists and validate before deserializing."
}

func impactDescription(cat string) string {
	switch cat {
	case "sql_query", "injection":
		return "An attacker could read, modify, or delete database records, potentially leading to full database compromise."
	case "command_exec":
		return "An attacker could execute arbitrary OS commands on the server, leading to complete system compromise."
	case "html_output", "xss":
		return "An attacker could inject malicious scripts that execute in other users' browsers, stealing sessions or credentials."
	case "file_write", "traversal":
		return "An attacker could read sensitive files or write to arbitrary locations on the filesystem."
	case "code_eval":
		return "An attacker could execute arbitrary code in the application's context."
	case "redirect":
		return "An attacker could redirect users to phishing or malware sites."
	case "url_fetch", "ssrf":
		return "An attacker could make the server send requests to internal services or cloud metadata endpoints."
	case "deserialize":
		return "An attacker could execute arbitrary code through crafted serialized payloads."
	case "secrets":
		return "Hardcoded secrets can be extracted from source code or compiled binaries."
	case "crypto":
		return "Weak cryptography can be broken, exposing sensitive data."
	default:
		return "This issue could be exploited to compromise the application's security."
	}
}

func architecturalAdvice(cat string) string {
	switch cat {
	case "injection":
		return "Multiple injection issues suggest you need a data access layer (ORM, query builder) that enforces parameterized queries by default."
	case "xss":
		return "Multiple XSS issues suggest you should use a template engine with auto-escaping enabled by default, and a Content-Security-Policy header."
	case "secrets":
		return "Multiple hardcoded secrets suggest you need a centralized configuration/secrets management solution (env vars, Vault, AWS Secrets Manager)."
	case "traversal":
		return "Multiple path traversal issues suggest you need a file access abstraction that enforces base directory constraints."
	default:
		return "Consider implementing a security middleware or abstraction layer to handle this category of vulnerability centrally."
	}
}

func categorizeRule(ruleID string) string {
	if strings.Contains(ruleID, "INJ") {
		return "injection"
	}
	if strings.Contains(ruleID, "XSS") {
		return "xss"
	}
	if strings.Contains(ruleID, "SEC") {
		return "secrets"
	}
	if strings.Contains(ruleID, "CRY") {
		return "crypto"
	}
	if strings.Contains(ruleID, "TRV") {
		return "traversal"
	}
	if strings.Contains(ruleID, "AUTH") {
		return "auth"
	}
	if strings.Contains(ruleID, "SSRF") {
		return "ssrf"
	}
	if strings.Contains(ruleID, "TAINT") {
		return "taint"
	}
	return "general"
}

func severityToPriority(sev rules.Severity) int {
	return int(rules.Critical) - int(sev) + 1
}

func sortHints(hints []Hint) {
	// Simple insertion sort — hint lists are small
	for i := 1; i < len(hints); i++ {
		for j := i; j > 0 && hints[j].Priority < hints[j-1].Priority; j-- {
			hints[j], hints[j-1] = hints[j-1], hints[j]
		}
	}
}

// SessionHints tracks hint patterns across a session for progressive improvement.
type SessionHints struct {
	TotalScans     int            `json:"total_scans"`
	TotalFindings  int            `json:"total_findings"`
	FixedFindings  int            `json:"fixed_findings"`
	PatternCounts  map[string]int `json:"pattern_counts"`
	LastScanTime   time.Time      `json:"last_scan_time"`
}
