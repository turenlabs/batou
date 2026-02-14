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
	case taint.SnkLDAP:
		return ldapFixExample(lang)
	case taint.SnkXPath:
		return xpathFixExample(lang)
	case taint.SnkHeader:
		return headerFixExample(lang)
	case taint.SnkTemplate:
		return templateFixExample(lang)
	case taint.SnkLog:
		return logFixExample(lang)
	case taint.SnkCrypto:
		return cryptoFixExample(lang)
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
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Instead of:\n" +
			"  exec(userInput)\n" +
			"  // Use execFile with explicit args (no shell):\n" +
			"  const { execFile } = require('child_process');\n" +
			"  execFile('ls', ['-la', sanitizedPath], callback);"
	case rules.LangJava:
		return "  // Instead of:\n" +
			"  Runtime.getRuntime().exec(userInput);\n" +
			"  // Use ProcessBuilder with explicit args:\n" +
			"  new ProcessBuilder(\"ls\", \"-la\", sanitizedPath).start();"
	case rules.LangPHP:
		return "  // Instead of:\n" +
			"  exec($userInput);\n" +
			"  // Use escapeshellarg for each argument:\n" +
			"  exec('ls -la ' . escapeshellarg($sanitizedPath));\n" +
			"  // Or better, avoid shell entirely and use specific PHP functions"
	case rules.LangRuby:
		return "  # Instead of:\n" +
			"  system(user_input)\n" +
			"  # Use array form (no shell):\n" +
			"  system('ls', '-la', sanitized_path)"
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
	case rules.LangJava:
		return "  // Use a template engine with auto-escaping (Thymeleaf, Freemarker) or:\n" +
			"  import org.apache.commons.text.StringEscapeUtils;\n" +
			"  String safe = StringEscapeUtils.escapeHtml4(userInput);"
	case rules.LangPHP:
		return "  // Instead of:\n" +
			"  echo $userInput;\n" +
			"  // Use htmlspecialchars:\n" +
			"  echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');"
	case rules.LangRuby:
		return "  # Rails auto-escapes in ERB views. For manual escaping:\n" +
			"  safe = ERB::Util.html_escape(user_input)\n" +
			"  # Or use sanitize helper for allowing safe HTML subset"
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
	case rules.LangPython:
		return "  # Validate path doesn't escape base directory:\n" +
			"  import os\n" +
			"  full = os.path.realpath(os.path.join(base_dir, user_path))\n" +
			"  if not full.startswith(os.path.realpath(base_dir)):\n" +
			"      raise ValueError(\"path traversal detected\")"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Validate path doesn't escape base directory:\n" +
			"  const path = require('path');\n" +
			"  const full = path.resolve(baseDir, userPath);\n" +
			"  if (!full.startsWith(path.resolve(baseDir))) {\n" +
			"      throw new Error('path traversal detected');\n" +
			"  }"
	case rules.LangJava:
		return "  // Validate path doesn't escape base directory:\n" +
			"  Path full = Paths.get(baseDir, userPath).normalize().toAbsolutePath();\n" +
			"  if (!full.startsWith(Paths.get(baseDir).toAbsolutePath())) {\n" +
			"      throw new SecurityException(\"path traversal detected\");\n" +
			"  }"
	case rules.LangPHP:
		return "  // Validate path doesn't escape base directory:\n" +
			"  $full = realpath($baseDir . '/' . $userPath);\n" +
			"  if ($full === false || strpos($full, realpath($baseDir)) !== 0) {\n" +
			"      throw new Exception('path traversal detected');\n" +
			"  }"
	case rules.LangRuby:
		return "  # Validate path doesn't escape base directory:\n" +
			"  full = File.realpath(File.join(base_dir, user_path))\n" +
			"  unless full.start_with?(File.realpath(base_dir))\n" +
			"    raise SecurityError, 'path traversal detected'\n" +
			"  end"
	default:
		return "  Canonicalize the path and verify it stays within the allowed directory."
	}
}

func redirectFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Validate redirect URL against an allowlist:\n" +
			"  allowed := map[string]bool{\"example.com\": true}\n" +
			"  u, err := url.Parse(target)\n" +
			"  if err != nil || (u.Host != \"\" && !allowed[u.Host]) {\n" +
			"      http.Error(w, \"invalid redirect\", http.StatusBadRequest)\n" +
			"      return\n" +
			"  }\n" +
			"  http.Redirect(w, r, u.Path, http.StatusFound)"
	case rules.LangPython:
		return "  # Validate redirect URL against an allowlist:\n" +
			"  from urllib.parse import urlparse\n" +
			"  parsed = urlparse(target)\n" +
			"  if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:\n" +
			"      abort(400, 'invalid redirect')\n" +
			"  return redirect(parsed.path)"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Validate redirect URL against an allowlist:\n" +
			"  const { URL } = require('url');\n" +
			"  try {\n" +
			"      const u = new URL(target, req.protocol + '://' + req.hostname);\n" +
			"      if (!allowedHosts.includes(u.hostname)) {\n" +
			"          return res.status(400).send('invalid redirect');\n" +
			"      }\n" +
			"  } catch { return res.status(400).send('invalid redirect'); }\n" +
			"  res.redirect(target);"
	case rules.LangJava:
		return "  // Validate redirect URL against an allowlist:\n" +
			"  URI uri = URI.create(target);\n" +
			"  if (uri.getHost() != null && !allowedHosts.contains(uri.getHost())) {\n" +
			"      response.sendError(400, \"invalid redirect\");\n" +
			"      return;\n" +
			"  }\n" +
			"  response.sendRedirect(uri.getPath());"
	case rules.LangPHP:
		return "  // Validate redirect URL against an allowlist:\n" +
			"  $parsed = parse_url($target);\n" +
			"  if (isset($parsed['host']) && !in_array($parsed['host'], $allowedHosts)) {\n" +
			"      http_response_code(400); die('invalid redirect');\n" +
			"  }\n" +
			"  header('Location: ' . $parsed['path']); exit;"
	case rules.LangRuby:
		return "  # Validate redirect URL against an allowlist:\n" +
			"  uri = URI.parse(target)\n" +
			"  if uri.host && !allowed_hosts.include?(uri.host)\n" +
			"    render plain: 'invalid redirect', status: 400 and return\n" +
			"  end\n" +
			"  redirect_to uri.path"
	default:
		return "  Validate redirect URL against an allowlist of trusted domains,\n" +
			"  or only allow relative paths (no protocol)."
	}
}

func evalFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Go does not have eval. If using a scripting engine,\n" +
			"  // run it in a sandbox with no access to os/exec or net."
	case rules.LangPython:
		return "  # Instead of:\n" +
			"  eval(user_input)\n" +
			"  # Use safe alternatives:\n" +
			"  import ast\n" +
			"  result = ast.literal_eval(user_input)  # only parses literals\n" +
			"  # Or for JSON:\n" +
			"  import json\n" +
			"  result = json.loads(user_input)"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Instead of:\n" +
			"  eval(userInput)\n" +
			"  // Use safe alternatives:\n" +
			"  const result = JSON.parse(userInput);\n" +
			"  // Or for expressions, use a sandboxed evaluator like 'mathjs'"
	case rules.LangPHP:
		return "  // Instead of:\n" +
			"  eval($userInput);\n" +
			"  // Use safe alternatives:\n" +
			"  $result = json_decode($userInput, true);\n" +
			"  // Never use eval, create_function, or preg_replace with /e"
	case rules.LangRuby:
		return "  # Instead of:\n" +
			"  eval(user_input)\n" +
			"  # Use safe alternatives:\n" +
			"  result = JSON.parse(user_input)\n" +
			"  # Or for math: use a sandboxed evaluator gem"
	default:
		return "  Never pass user input to eval/exec.\n" +
			"  Use safe alternatives: JSON.parse(), ast.literal_eval(), etc."
	}
}

func ssrfFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Validate URL against an allowlist:\n" +
			"  u, err := url.Parse(target)\n" +
			"  if err != nil || !allowedHosts[u.Hostname()] {\n" +
			"      return fmt.Errorf(\"blocked: host %s not allowed\", u.Hostname())\n" +
			"  }\n" +
			"  // Also resolve DNS and block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)"
	case rules.LangPython:
		return "  # Validate URL against an allowlist:\n" +
			"  from urllib.parse import urlparse\n" +
			"  parsed = urlparse(target)\n" +
			"  if parsed.hostname not in ALLOWED_HOSTS:\n" +
			"      raise ValueError(f'blocked: host {parsed.hostname} not allowed')\n" +
			"  # Also resolve DNS and block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Validate URL against an allowlist:\n" +
			"  const u = new URL(target);\n" +
			"  if (!allowedHosts.includes(u.hostname)) {\n" +
			"      throw new Error(`blocked: host ${u.hostname} not allowed`);\n" +
			"  }\n" +
			"  // Also resolve DNS and block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)"
	case rules.LangJava:
		return "  // Validate URL against an allowlist:\n" +
			"  URI uri = URI.create(target);\n" +
			"  if (!allowedHosts.contains(uri.getHost())) {\n" +
			"      throw new SecurityException(\"blocked: host \" + uri.getHost() + \" not allowed\");\n" +
			"  }\n" +
			"  // Also resolve DNS and block internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x)"
	default:
		return "  Validate URLs against an allowlist of trusted hosts.\n" +
			"  Block internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.169.254)."
	}
}

func deserializationFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangPython:
		return "  # Instead of:\n" +
			"  pickle.loads(user_data)\n" +
			"  # Use safe formats:\n" +
			"  import json\n" +
			"  data = json.loads(user_data)\n" +
			"  # If pickle is required, never unpickle untrusted data"
	case rules.LangJava:
		return "  // Instead of:\n" +
			"  ObjectInputStream ois = new ObjectInputStream(input);\n" +
			"  Object obj = ois.readObject();\n" +
			"  // Use an allowlist filter:\n" +
			"  ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\"com.myapp.*;!*\");\n" +
			"  ois.setObjectInputFilter(filter);\n" +
			"  // Or use JSON (Jackson/Gson) instead of Java serialization"
	case rules.LangPHP:
		return "  // Instead of:\n" +
			"  unserialize($userData);\n" +
			"  // Use safe formats:\n" +
			"  $data = json_decode($userData, true);\n" +
			"  // If unserialize is required, use allowed_classes:\n" +
			"  unserialize($data, ['allowed_classes' => ['SafeClass']]);"
	case rules.LangRuby:
		return "  # Instead of:\n" +
			"  Marshal.load(user_data)\n" +
			"  # Use safe formats:\n" +
			"  data = JSON.parse(user_data)\n" +
			"  # Never use Marshal.load or YAML.load on untrusted data"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Use JSON.parse() instead of deserializing with libraries like\n" +
			"  // node-serialize or js-yaml (unsafe mode).\n" +
			"  const data = JSON.parse(userInput);\n" +
			"  // For YAML, use yaml.load with SAFE_SCHEMA"
	default:
		return "  Use safe formats (JSON) instead of language-native serialization.\n" +
			"  If deserialization is required, use allowlists and validate before deserializing."
	}
}

func ldapFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangJava:
		return "  // Use parameterized LDAP filters:\n" +
			"  String filter = \"(&(uid={0})(objectClass=person))\";\n" +
			"  ctx.search(baseDN, filter, new Object[]{userInput}, searchControls);"
	case rules.LangPython:
		return "  # Escape LDAP special characters:\n" +
			"  from ldap3.utils.conv import escape_filter_chars\n" +
			"  safe = escape_filter_chars(user_input)\n" +
			"  conn.search(base_dn, f'(uid={safe})')"
	default:
		return "  Escape LDAP special characters (*, (, ), \\, NUL) in user input\n" +
			"  before including it in LDAP filters."
	}
}

func xpathFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangJava:
		return "  // Use parameterized XPath with XPathVariableResolver:\n" +
			"  xpath.setXPathVariableResolver(v -> userInput);\n" +
			"  xpath.evaluate(\"/users/user[@name=$name]\", doc);"
	default:
		return "  Use parameterized XPath queries or escape special characters\n" +
			"  (', \", <, >, &) before including user input in XPath expressions."
	}
}

func headerFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Validate header value has no CRLF characters:\n" +
			"  if strings.ContainsAny(value, \"\\r\\n\") {\n" +
			"      return errors.New(\"header injection detected\")\n" +
			"  }\n" +
			"  w.Header().Set(name, value)"
	case rules.LangPython:
		return "  # Frameworks like Django/Flask reject CRLF in headers by default.\n" +
			"  # If setting headers manually, strip CR/LF:\n" +
			"  safe_value = value.replace('\\r', '').replace('\\n', '')"
	default:
		return "  Strip or reject carriage return (\\r) and newline (\\n)\n" +
			"  characters from header values to prevent header injection."
	}
}

func templateFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangPython:
		return "  # Never pass user input as the template source:\n" +
			"  # BAD:  Template(user_input).render()\n" +
			"  # GOOD: render_template('page.html', data=user_input)\n" +
			"  # Use Jinja2 sandbox if dynamic templates are truly needed:\n" +
			"  from jinja2.sandbox import SandboxedEnvironment\n" +
			"  env = SandboxedEnvironment()"
	case rules.LangJava:
		return "  // Never pass user input as the template source.\n" +
			"  // Use template files and pass user data as variables:\n" +
			"  model.addAttribute(\"data\", userInput);\n" +
			"  return \"template_file\";  // resolved by template engine"
	case rules.LangJavaScript, rules.LangTypeScript:
		return "  // Never pass user input as template source:\n" +
			"  // BAD:  ejs.render(userInput)\n" +
			"  // GOOD: ejs.render(templateFile, { data: userInput })\n" +
			"  // Use auto-escaping and avoid unescaped output (<%- %>)"
	default:
		return "  Never pass user input as the template source.\n" +
			"  Pass user data as template variables, and enable auto-escaping."
	}
}

func logFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Sanitize log input to prevent log injection/forging:\n" +
			"  safe := strings.ReplaceAll(userInput, \"\\n\", \"\")\n" +
			"  safe = strings.ReplaceAll(safe, \"\\r\", \"\")\n" +
			"  log.Printf(\"user action: %s\", safe)"
	case rules.LangPython:
		return "  # Sanitize log input to prevent log injection:\n" +
			"  safe = user_input.replace('\\n', '').replace('\\r', '')\n" +
			"  logger.info('user action: %s', safe)"
	case rules.LangJava:
		return "  // Sanitize log input to prevent log injection (CRLF):\n" +
			"  String safe = userInput.replaceAll(\"[\\\\r\\\\n]\", \"\");\n" +
			"  logger.info(\"user action: {}\", safe);"
	default:
		return "  Strip newline characters (\\r, \\n) from user input before logging\n" +
			"  to prevent log injection and log forging attacks."
	}
}

func cryptoFixExample(lang rules.Language) string {
	switch lang {
	case rules.LangGo:
		return "  // Never use user input as crypto keys or IVs.\n" +
			"  // Derive keys from passwords using a KDF:\n" +
			"  key, _ := scrypt.Key(password, salt, 32768, 8, 1, 32)"
	case rules.LangPython:
		return "  # Never use user input as crypto keys or IVs.\n" +
			"  # Derive keys from passwords using a KDF:\n" +
			"  from cryptography.hazmat.primitives.kdf.scrypt import Scrypt\n" +
			"  kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)\n" +
			"  key = kdf.derive(password)"
	case rules.LangJava:
		return "  // Never use user input as crypto keys or IVs.\n" +
			"  // Derive keys from passwords using PBKDF2:\n" +
			"  SecretKeyFactory f = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");\n" +
			"  KeySpec spec = new PBEKeySpec(password, salt, 600000, 256);\n" +
			"  SecretKey key = f.generateSecret(spec);"
	default:
		return "  Never use user-controlled input directly as cryptographic keys or IVs.\n" +
			"  Derive keys using a secure KDF (scrypt, Argon2, PBKDF2)."
	}
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
	case "crypto", "crypto_input":
		return "Weak cryptography can be broken, exposing sensitive data."
	case "ldap_query":
		return "An attacker could modify LDAP queries to bypass authentication or access unauthorized directory entries."
	case "xpath_query":
		return "An attacker could modify XPath queries to extract unauthorized data from XML documents."
	case "http_header":
		return "An attacker could inject CRLF sequences to set arbitrary headers or split HTTP responses."
	case "template_render":
		return "An attacker could execute arbitrary code via server-side template injection (SSTI)."
	case "log_output", "logging":
		return "An attacker could forge log entries or inject malicious content into log files."
	case "xxe":
		return "An attacker could read local files, perform SSRF, or cause denial of service via XML external entities."
	case "cors":
		return "Misconfigured CORS allows unauthorized cross-origin access to sensitive APIs."
	case "auth":
		return "Weak authentication or authorization could allow unauthorized access to protected resources."
	case "memory":
		return "Memory safety issues could lead to crashes, information disclosure, or code execution."
	case "prototype":
		return "Prototype pollution could modify application behavior or lead to remote code execution."
	case "massassign":
		return "Mass assignment could allow attackers to modify protected fields like roles or permissions."
	case "graphql":
		return "GraphQL vulnerabilities could allow query abuse, data exfiltration, or denial of service."
	case "misconfig":
		return "Security misconfiguration could expose debug info, enable unsafe features, or weaken defenses."
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
	case "ssrf":
		return "Multiple SSRF issues suggest you need a centralized HTTP client wrapper that validates URLs against an allowlist and blocks internal IP ranges."
	case "auth":
		return "Multiple auth issues suggest you need a centralized authentication/authorization middleware rather than per-endpoint checks."
	case "crypto":
		return "Multiple crypto issues suggest you need a crypto utility module that enforces safe algorithms (AES-256-GCM, SHA-256+, Argon2/scrypt) by default."
	case "deserialize":
		return "Multiple deserialization issues suggest you should standardize on safe formats (JSON) and ban native deserialization of untrusted data."
	case "logging":
		return "Multiple log injection issues suggest you need a structured logging library that automatically sanitizes inputs."
	case "redirect":
		return "Multiple redirect issues suggest you need a centralized redirect helper that validates destinations against an allowlist."
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
	if strings.Contains(ruleID, "DESER") {
		return "deserialize"
	}
	if strings.Contains(ruleID, "REDIR") {
		return "redirect"
	}
	if strings.Contains(ruleID, "NOSQL") {
		return "injection"
	}
	if strings.Contains(ruleID, "XXE") {
		return "xxe"
	}
	if strings.Contains(ruleID, "CORS") {
		return "cors"
	}
	if strings.Contains(ruleID, "LOG") {
		return "logging"
	}
	if strings.Contains(ruleID, "MEM") {
		return "memory"
	}
	if strings.Contains(ruleID, "PROTO") {
		return "prototype"
	}
	if strings.Contains(ruleID, "MASS") {
		return "massassign"
	}
	if strings.Contains(ruleID, "GQL") {
		return "graphql"
	}
	if strings.Contains(ruleID, "MISCONF") {
		return "misconfig"
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
