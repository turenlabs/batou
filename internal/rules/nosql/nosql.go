package nosql

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// GTSS-NOSQL-001: MongoDB $where injection (code execution)
var (
	// $where with template literal interpolation: $where: `this.field === '${input}'`
	reWhereTemplateLiteral = regexp.MustCompile("`[^`]*\\$where[^`]*\\$\\{")
	// $where with string concatenation: "$where": "..." + variable
	// Handle double-quoted and single-quoted strings separately to allow the
	// other quote type inside (e.g., "this.name == '" + var)
	reWhereConcatStr = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*(?:"[^"]*"\s*\+|'[^']*'\s*\+|[^"'\s][^,}]*\+)`)
	// $where with template literal value: $where: `this.x === '${...}'`
	reWhereTemplateLiteralValue = regexp.MustCompile("(?i)['\"]\\$where['\"]\\s*(?::|=>)\\s*`[^`]*\\$\\{")
	// $where with f-string (Python): "$where": f"this.x == '{var}'"
	reWhereFString = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*f["']`)
	// $where with .format() (Python)
	reWhereFormat = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*["'][^"']*["']\s*\.format\(`)
	// $where with % formatting (Python)
	reWherePercent = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*["'][^"']*%[sv][^"']*["']\s*%`)
	// eval() inside MongoDB $where expression
	reWhereEval = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*["'][^"']*\beval\s*\(`)
	// Ruby string interpolation in $where (supports both : and => syntax)
	reWhereRubyInterp = regexp.MustCompile(`(?i)['"]\$where['"]\s*(?::|=>)\s*"[^"]*#\{`)
)

// GTSS-NOSQL-002: MongoDB operator injection
var (
	// Direct passthrough of req.body/req.query/req.params to query methods
	reOperatorDirectPassthrough = regexp.MustCompile(`(?i)\.(?:find|findOne|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments|findOneAndUpdate|findOneAndDelete|findOneAndReplace)\s*\(\s*req\.(?:body|query|params)\b`)
	// Model.findOne({ field: req.body.field }) pattern
	reOperatorModelQuery = regexp.MustCompile(`(?i)(?:Model|Collection)\.\w+\(\s*\{[^}]*:\s*req\.(?:body|query|params)\.\w+`)
	// JSON.parse of user input in query
	reOperatorJSONParse = regexp.MustCompile(`(?i)\.(?:find|findOne|aggregate|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*JSON\.parse\s*\(`)
	// MongoDB query with string concatenation in query object
	reOperatorQueryConcat = regexp.MustCompile(`(?i)\.(?:find|findOne|aggregate|updateOne|updateMany|deleteOne|deleteMany|remove|count|countDocuments)\s*\(\s*(?:["'][^"']*["']\s*\+|\{[^}]*:\s*[^"'\s{][^,}]*\+)`)
	// $gt/$ne/$gte/$lte operators with req input (operator injection indicator)
	reOperatorInjectionPattern = regexp.MustCompile(`(?i)\{\s*['"]\$(?:gt|gte|lt|lte|ne|in|nin|regex|exists|not|or|and|nor|where|elemMatch)['"]\s*:\s*(?:req\.(?:body|query|params)|['"]{2})`)
	// Python pymongo with unsanitized input: collection.find(user_input) or find(request.form)
	reOperatorPymongo = regexp.MustCompile(`(?i)(?:collection|db\[\s*["'][^"']+["']\s*\]|db\.\w+)\.(?:find|find_one|update_one|update_many|delete_one|delete_many|count_documents|aggregate)\s*\(\s*(?:request\.(?:form|args|json|data|values)|user_input|query_filter|filter_doc)\b`)
	// Ruby mongoid: Model.where(params[:field])
	reOperatorMongoid = regexp.MustCompile(`(?i)\.(?:where|find_by|find|any_of|all_of)\s*\(\s*params\[`)
	// mongoose.connection.db.collection().find() with string concat
	reOperatorMongooseRaw = regexp.MustCompile(`(?i)mongoose\.connection\.db\.collection\([^)]*\)\.(?:find|findOne|aggregate)\s*\(`)
	// Aggregation pipeline with user-controlled stages
	reOperatorAggPassthrough = regexp.MustCompile(`(?i)\.aggregate\s*\(\s*(?:req\.(?:body|query|params)|JSON\.parse)`)
)

// GTSS-NOSQL-003: Raw query with user input
var (
	// MongoDB $regex with user input
	reRawRegex = regexp.MustCompile(`(?i)['"]\$regex['"]\s*:\s*(?:req\.(?:body|query|params)\.\w+|[^"'\s{][^,}]*\+|f["']|[^"'\s,}]+\.(?:body|query|params|input|data)\.\w+)`)
	// MongoDB mapReduce/group with function (potential code injection)
	reRawMapReduce = regexp.MustCompile(`(?i)\.(?:mapReduce|group)\s*\([^)]*(?:function|=>)`)
	// $lookup with user-controlled "from" field
	reRawAggLookup = regexp.MustCompile(
		`(?i)['"]\$lookup['"]\s*:\s*\{[^}]*['"]from['"]\s*:\s*` +
			`(?:req\.(?:body|query|params)|[^"'\s{][^,}]*\+|f["']|[^"'\s{,}]+\.(?:body|query|params|input|data)\.\w+)`)
	// $merge/$out with user-controlled collection
	reRawAggMergeOut = regexp.MustCompile(
		`(?i)['"]\$(?:merge|out)['"]\s*:\s*` +
			`(?:req\.(?:body|query|params)|[^"'\s{][^,}]*\+|f["']|[^"'\s{,}]+\.(?:body|query|params|input|data)\.\w+)`)
	// eval-like server-side JS execution
	reRawServerEval = regexp.MustCompile(`(?i)db\.eval\s*\(|\.runCommand\s*\(\s*\{[^}]*['"]\$eval['"]`)
)

// Comment detection
var reLineComment = regexp.MustCompile(`^\s*(?://|#|--|;|%|/\*)`)

func isCommentLine(line string) bool {
	return reLineComment.MatchString(line)
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// ---------------------------------------------------------------------------
// GTSS-NOSQL-001: MongoDB $where Injection
// ---------------------------------------------------------------------------

type WhereInjection struct{}

func (r WhereInjection) ID() string                     { return "GTSS-NOSQL-001" }
func (r WhereInjection) Name() string                   { return "MongoDB $where Injection" }
func (r WhereInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r WhereInjection) Description() string {
	return "Detects MongoDB $where operator with string interpolation or concatenation, enabling server-side JavaScript execution."
}
func (r WhereInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangRuby,
	}
}

func (r WhereInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
		lang rules.Language
	}

	patterns := []pattern{
		{reWhereTemplateLiteral, "high", "$where with template literal interpolation (server-side JS execution)", rules.LangAny},
		{reWhereConcatStr, "high", "$where with string concatenation (server-side JS execution)", rules.LangAny},
		{reWhereTemplateLiteralValue, "high", "$where with template literal value (server-side JS execution)", rules.LangAny},
		{reWhereFString, "high", "$where with Python f-string (server-side JS execution)", rules.LangPython},
		{reWhereFormat, "high", "$where with .format() (server-side JS execution)", rules.LangPython},
		{reWherePercent, "high", "$where with % formatting (server-side JS execution)", rules.LangPython},
		{reWhereEval, "high", "$where with eval() (server-side JS execution)", rules.LangAny},
		{reWhereRubyInterp, "high", "$where with Ruby string interpolation (server-side JS execution)", rules.LangRuby},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if p.lang != rules.LangAny && p.lang != ctx.Language {
				continue
			}
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "MongoDB $where Injection: " + p.desc,
					Description:   "The $where operator executes JavaScript on the MongoDB server. User-controlled input in $where enables NoSQL injection and arbitrary code execution.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Remove $where and use standard MongoDB query operators ($eq, $regex, $in, etc.). If $where is required, never include user input in the expression string.",
					CWEID:         "CWE-943",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "nosql", "mongodb", "where"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-NOSQL-002: MongoDB Operator Injection
// ---------------------------------------------------------------------------

type OperatorInjection struct{}

func (r OperatorInjection) ID() string                     { return "GTSS-NOSQL-002" }
func (r OperatorInjection) Name() string                   { return "MongoDB Operator Injection" }
func (r OperatorInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r OperatorInjection) Description() string {
	return "Detects patterns where user input is used as MongoDB query operators, enabling query manipulation via operator injection ($gt, $ne, etc.)."
}
func (r OperatorInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangRuby,
	}
}

func (r OperatorInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
		lang rules.Language
	}

	patterns := []pattern{
		{reOperatorDirectPassthrough, "high", "req.body/query/params passed directly to MongoDB query method", rules.LangAny},
		{reOperatorModelQuery, "medium", "Model query with req.body/query/params field value (may allow operator injection)", rules.LangAny},
		{reOperatorJSONParse, "high", "JSON.parse of user input in MongoDB query", rules.LangAny},
		{reOperatorQueryConcat, "medium", "MongoDB query with string concatenation", rules.LangAny},
		{reOperatorInjectionPattern, "high", "MongoDB query operator ($gt/$ne/etc.) with user input", rules.LangAny},
		{reOperatorPymongo, "high", "pymongo query with unsanitized user input", rules.LangPython},
		{reOperatorMongoid, "high", "Mongoid query with unsanitized params", rules.LangRuby},
		{reOperatorMongooseRaw, "medium", "Raw mongoose connection query (verify input is sanitized)", rules.LangAny},
		{reOperatorAggPassthrough, "high", "Aggregation pipeline with user-controlled input", rules.LangAny},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if p.lang != rules.LangAny && p.lang != ctx.Language {
				continue
			}
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "MongoDB Operator Injection: " + p.desc,
					Description:   "User input passed to MongoDB queries without validation can contain query operators ($gt, $ne, $regex) that manipulate query logic, bypassing authentication or exfiltrating data.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Cast user input to expected types (e.g., String(value), parseInt(value)). Use a schema validator (e.g., Joi, express-mongo-sanitize) to strip $ operators from input.",
					CWEID:         "CWE-943",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "nosql", "mongodb", "operator"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// GTSS-NOSQL-003: Raw Query with User Input
// ---------------------------------------------------------------------------

type RawQueryInjection struct{}

func (r RawQueryInjection) ID() string                     { return "GTSS-NOSQL-003" }
func (r RawQueryInjection) Name() string                   { return "MongoDB Raw Query Injection" }
func (r RawQueryInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r RawQueryInjection) Description() string {
	return "Detects raw MongoDB queries with user-controlled input in $regex, aggregation pipelines, mapReduce, or server-side eval."
}
func (r RawQueryInjection) Languages() []rules.Language {
	return []rules.Language{
		rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangRuby,
	}
}

func (r RawQueryInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	type pattern struct {
		re   *regexp.Regexp
		conf string
		desc string
		sev  rules.Severity
	}

	patterns := []pattern{
		{reRawRegex, "high", "$regex with user-controlled input (ReDoS or data exfiltration)", rules.High},
		{reRawMapReduce, "medium", "mapReduce/group with function (potential code injection)", rules.High},
		{reRawAggLookup, "high", "$lookup with user-controlled 'from' collection", rules.High},
		{reRawAggMergeOut, "high", "$merge/$out with user-controlled collection name", rules.High},
		{reRawServerEval, "high", "Server-side eval or $eval (arbitrary code execution)", rules.Critical},
	}

	for i, line := range lines {
		if isCommentLine(line) {
			continue
		}
		for _, p := range patterns {
			if loc := p.re.FindStringIndex(line); loc != nil {
				matched := truncate(line[loc[0]:loc[1]], 120)
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      p.sev,
					SeverityLabel: p.sev.String(),
					Title:         "MongoDB Raw Query: " + p.desc,
					Description:   "Raw MongoDB operations with user-controlled input can enable data exfiltration, denial of service, or arbitrary code execution on the database server.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   matched,
					Suggestion:    "Validate and sanitize all user input before using in MongoDB operations. Use query builders with typed parameters. Avoid server-side JavaScript execution.",
					CWEID:         "CWE-943",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    p.conf,
					Tags:          []string{"injection", "nosql", "mongodb", "raw-query"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(WhereInjection{})
	rules.Register(OperatorInjection{})
	rules.Register(RawQueryInjection{})
}
