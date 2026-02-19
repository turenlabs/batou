package framework

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns -- Framework extensions
// ---------------------------------------------------------------------------

// BATOU-FW-EXPRESS-009: Express res.redirect with user input (open redirect)
var (
	reExpressRedirectDirect = regexp.MustCompile(`res\.redirect\s*\(\s*req\.(?:query|body|params)\s*\.`)
	reExpressRedirectVar    = regexp.MustCompile(`res\.redirect\s*\(\s*req\.(?:query|body|params)\s*\[`)
	reExpressRedirectSafe   = regexp.MustCompile(`(?i)(?:allowlist|whitelist|allowed\w*|validate\w*|isValid\w*|isSafe\w*|sanitize\w*|parseUrl|new\s+URL)`)
)

// BATOU-FW-NEXTJS-009: Next.js getServerSideProps SQL injection via query params
var (
	reNextGSSPFunction  = regexp.MustCompile(`(?:export\s+(?:async\s+)?function|const)\s+getServerSideProps`)
	reNextContextQuery  = regexp.MustCompile(`context\.(?:query|params)`)
	reNextContextDestr  = regexp.MustCompile(`(?:query|params)\s*\}\s*=\s*context`)
	reNextDBCall        = regexp.MustCompile(`(?i)(?:\.query\s*\(|\.execute\s*\(|\.findOne\s*\(|\.find\s*\(|\.where\s*\(|\.raw\s*\(|prisma\.|sequelize\.|knex\s*\(|db\.)`)
	reNextParamQuery    = regexp.MustCompile(`(?i)(?:\.query\s*\(|\.execute\s*\(|\.raw\s*\(|\.findOne\s*\(|\.find\s*\().*(?:context\.query|context\.params|\$\{)`)
	reNextSQLConcat     = regexp.MustCompile("(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\\b[^`]*\\$\\{")
	reNextParamSQL      = regexp.MustCompile(`(?i)(?:\.query|\.execute|\.raw)\s*\(\s*` + "`" + `[^` + "`" + `]*\$\{`)
	reNextParamSQLConcat = regexp.MustCompile(`(?i)(?:\.query|\.execute|\.raw)\s*\([^)]*\+`)
	reNextParamSafe     = regexp.MustCompile(`(?i)(?:parameterized|prepared|sanitize|escape|parseInt|Number\(|validate|zod|yup|joi)`)
)

// BATOU-FW-FASTAPI-011: FastAPI endpoint with unvalidated path/query params
var (
	reFastapiPlainParam     = regexp.MustCompile(`(?:def\s+\w+\s*\([^)]*\b(?:item_id|user_id|id|name|query|search|filter|sort|page|limit|offset)\s*(?:,|\)))|(?:def\s+\w+\s*\([^)]*\b\w+\s*:\s*str\s*(?:,|\)))`)
	reFastapiValidatedParam = regexp.MustCompile(`(?:Query\s*\(|Path\s*\(|Body\s*\(|Header\s*\(|Cookie\s*\(|Depends\s*\(|Field\s*\(|Annotated\s*\[)`)
	reFastapiRouteDecorator = regexp.MustCompile(`@(?:app|router)\.(?:get|post|put|delete|patch)\s*\(`)
)

// BATOU-FW-GIN-011: Gin db.Raw/db.Exec with fmt.Sprintf (SQL injection)
var (
	reGinRawSprintf = regexp.MustCompile(`db\.(?:Raw|Exec)\s*\(\s*fmt\.Sprintf\s*\(`)
	reGinRawConcat  = regexp.MustCompile(`db\.(?:Raw|Exec)\s*\(\s*(?:[a-zA-Z_]\w*|"[^"]*")\s*\+`)
	reGinRawFmtVar  = regexp.MustCompile(`db\.(?:Raw|Exec)\s*\(\s*fmt\.Sprintf`)
)

func init() {
	rules.Register(&ExpressOpenRedirect{})
	rules.Register(&NextJSGSSPInjection{})
	rules.Register(&FastAPIUnvalidatedParam{})
	rules.Register(&GinRawSQLFormat{})
}

// ---------------------------------------------------------------------------
// BATOU-FW-EXPRESS-009: Express res.redirect with user input
// ---------------------------------------------------------------------------

type ExpressOpenRedirect struct{}

func (r *ExpressOpenRedirect) ID() string                      { return "BATOU-FW-EXPRESS-009" }
func (r *ExpressOpenRedirect) Name() string                    { return "ExpressOpenRedirect" }
func (r *ExpressOpenRedirect) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressOpenRedirect) Description() string {
	return "Detects Express res.redirect() with user-controlled URL from req.query, req.body, or req.params without validation."
}
func (r *ExpressOpenRedirect) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressOpenRedirect) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reExpressRedirectDirect.FindString(line); m != "" {
			matched = m
		} else if m := reExpressRedirectVar.FindString(line); m != "" {
			matched = m
		}

		if matched == "" {
			continue
		}

		// Check for URL validation nearby
		start := i - 10
		if start < 0 {
			start = 0
		}
		end := i + 5
		if end > len(lines) {
			end = len(lines)
		}
		hasValidation := false
		for _, contextLine := range lines[start:end] {
			if reExpressRedirectSafe.MatchString(contextLine) {
				hasValidation = true
				break
			}
		}
		if hasValidation {
			continue
		}

		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Express res.redirect() with user-controlled URL (open redirect)",
			Description:   "res.redirect() is called with a URL directly from req.query, req.body, or req.params without validation. An attacker can craft a link that redirects users to a phishing site or malicious page through your trusted domain.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Validate redirect URLs against an allowlist of permitted paths or domains. Use relative paths only: res.redirect('/dashboard'). If external URLs are needed, parse with new URL() and verify the host against a trusted list.",
			CWEID:         "CWE-601",
			OWASPCategory: "A01:2021-Broken Access Control",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"framework", "express", "open-redirect"},
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-NEXTJS-009: Next.js getServerSideProps SQL injection
// ---------------------------------------------------------------------------

type NextJSGSSPInjection struct{}

func (r *NextJSGSSPInjection) ID() string                      { return "BATOU-FW-NEXTJS-009" }
func (r *NextJSGSSPInjection) Name() string                    { return "NextJSGSSPInjection" }
func (r *NextJSGSSPInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *NextJSGSSPInjection) Description() string {
	return "Detects Next.js getServerSideProps passing unsanitized context.query/params to database calls, enabling SQL injection in server-side rendering."
}
func (r *NextJSGSSPInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NextJSGSSPInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Must have getServerSideProps
	if !reNextGSSPFunction.MatchString(ctx.Content) {
		return nil
	}

	// Must reference context.query or destructure query from context
	hasQueryAccess := reNextContextQuery.MatchString(ctx.Content) || reNextContextDestr.MatchString(ctx.Content)
	if !hasQueryAccess {
		return nil
	}

	// Must have database calls
	if !reNextDBCall.MatchString(ctx.Content) {
		return nil
	}

	// If parameterized queries or validation is present, skip
	if reNextParamSafe.MatchString(ctx.Content) {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	inGSSP := false
	braceDepth := 0

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		if reNextGSSPFunction.MatchString(line) {
			inGSSP = true
			braceDepth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}

		if inGSSP {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")

			// Look for SQL/DB calls with query params
			if reNextParamSQL.MatchString(line) || reNextParamSQLConcat.MatchString(line) || reNextParamQuery.MatchString(line) {
				matched := strings.TrimSpace(line)
				if len(matched) > 120 {
					matched = matched[:120] + "..."
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Next.js getServerSideProps SQL injection via query params",
					Description:   "context.query or context.params values are passed to database operations inside getServerSideProps without sanitization. Since SSR runs on the server, unsanitized query parameters in SQL create a direct SQL injection vulnerability.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Use parameterized queries: db.query('SELECT * FROM users WHERE id = $1', [context.query.id]). With ORMs, use their built-in parameter binding. Validate/sanitize query params with parseInt() for numeric IDs or use a validation library like zod.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"framework", "nextjs", "sql-injection", "ssr"},
				})
			}

			if braceDepth <= 0 {
				inGSSP = false
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-FASTAPI-011: FastAPI endpoint with unvalidated params
// ---------------------------------------------------------------------------

type FastAPIUnvalidatedParam struct{}

func (r *FastAPIUnvalidatedParam) ID() string                      { return "BATOU-FW-FASTAPI-011" }
func (r *FastAPIUnvalidatedParam) Name() string                    { return "FastAPIUnvalidatedParam" }
func (r *FastAPIUnvalidatedParam) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FastAPIUnvalidatedParam) Description() string {
	return "Detects FastAPI endpoint parameters without Query(), Path(), or other validators, accepting raw unvalidated input."
}
func (r *FastAPIUnvalidatedParam) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *FastAPIUnvalidatedParam) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding

	// Must have FastAPI route decorators
	if !reFastapiRouteDecorator.MatchString(ctx.Content) {
		return nil
	}

	// If the file already uses validators, it's likely well-structured
	if reFastapiValidatedParam.MatchString(ctx.Content) {
		return nil
	}

	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}

		if !reFastapiRouteDecorator.MatchString(line) {
			continue
		}

		// Look ahead for the function definition with plain parameters
		lookAhead := 5
		if i+lookAhead > len(lines) {
			lookAhead = len(lines) - i
		}
		block := strings.Join(lines[i:i+lookAhead], "\n")

		if reFastapiPlainParam.MatchString(block) {
			matched := strings.TrimSpace(line)
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "FastAPI endpoint with unvalidated parameters",
				Description:   "This FastAPI endpoint accepts parameters without using Query(), Path(), Body(), or Field() validators. Without validators, parameters are accepted as-is without type coercion, range checks, or format validation.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use FastAPI validators: Query(min_length=1, max_length=100), Path(gt=0), Body(embed=True). Example: async def get_user(user_id: int = Path(..., gt=0), q: str = Query(None, max_length=50)).",
				CWEID:         "CWE-20",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"framework", "fastapi", "validation", "input-validation"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-FW-GIN-011: Gin db.Raw/db.Exec with fmt.Sprintf (SQL injection)
// ---------------------------------------------------------------------------

type GinRawSQLFormat struct{}

func (r *GinRawSQLFormat) ID() string                      { return "BATOU-FW-GIN-011" }
func (r *GinRawSQLFormat) Name() string                    { return "GinRawSQLFormat" }
func (r *GinRawSQLFormat) DefaultSeverity() rules.Severity { return rules.High }
func (r *GinRawSQLFormat) Description() string {
	return "Detects Gin handlers using db.Raw() or db.Exec() with fmt.Sprintf or string concatenation to build SQL queries."
}
func (r *GinRawSQLFormat) Languages() []rules.Language {
	return []rules.Language{rules.LangGo}
}

func (r *GinRawSQLFormat) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Must be in a file that uses Gin context
	if !strings.Contains(ctx.Content, "gin.Context") && !strings.Contains(ctx.Content, "*gin.") {
		return nil
	}

	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*") {
			continue
		}

		var matched string
		if m := reGinRawSprintf.FindString(line); m != "" {
			matched = m
		} else if m := reGinRawConcat.FindString(line); m != "" {
			matched = m
		}

		if matched == "" {
			continue
		}

		if len(matched) > 120 {
			matched = matched[:120] + "..."
		}

		findings = append(findings, rules.Finding{
			RuleID:        r.ID(),
			Severity:      r.DefaultSeverity(),
			SeverityLabel: r.DefaultSeverity().String(),
			Title:         "Gin handler with db.Raw/db.Exec using fmt.Sprintf (SQL injection)",
			Description:   "db.Raw() or db.Exec() is called with fmt.Sprintf() or string concatenation in a Gin handler. This builds SQL queries by interpolating values directly into the query string instead of using parameterized placeholders, enabling SQL injection.",
			FilePath:      ctx.FilePath,
			LineNumber:    i + 1,
			MatchedText:   matched,
			Suggestion:    "Use parameterized queries with GORM: db.Raw(\"SELECT * FROM users WHERE id = ?\", userID) or db.Where(\"name = ?\", name).Find(&users). Never use fmt.Sprintf to build SQL.",
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Language:      ctx.Language,
			Confidence:    "high",
			Tags:          []string{"framework", "gin", "sql-injection", "gorm"},
		})
	}
	return findings
}
