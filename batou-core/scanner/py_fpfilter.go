package scanner

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// pyFilterAllFindings suppresses Python findings (regex + taint) where
// framework-safe patterns make the finding a false positive.
func pyFilterAllFindings(content string, findings []rules.Finding) []rules.Finding {
	lines := strings.Split(content, "\n")

	// Pre-compute file-level signals.
	hasSQLAlchemy := pyHasSQLAlchemyORM.MatchString(content)
	hasDjangoORM := pyHasDjangoORM.MatchString(content)
	hasJWTEncode := pyHasJWTEncode.MatchString(content)
	hasPydantic := pyHasPydantic.MatchString(content)

	kept := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		lineIdx := f.LineNumber - 1
		cwe := strings.TrimPrefix(f.CWEID, "CWE-")

		switch cwe {
		case "89": // SQL injection
			// SQLAlchemy ORM: select().where(), .filter(), .filter_by()
			if hasSQLAlchemy && pyIsSQLAlchemyQuery(lines, lineIdx) {
				continue
			}
			// Django ORM: Model.objects.filter(), .get(), .exclude()
			if hasDjangoORM && pyIsDjangoQuery(lines, lineIdx) {
				continue
			}

		case "22", "73": // Path traversal / file operations
			// jwt.encode is NOT a file write — it returns a token string
			if hasJWTEncode && pyIsJWTEncode(lines, lineIdx) {
				continue
			}

		case "502": // Deserialization
			// Pydantic model validation is safe deserialization
			if hasPydantic && pyIsPydanticValidation(lines, lineIdx) {
				continue
			}
			// json.loads into typed assignment is safe
			if pyIsSafeJSONParse(lines, lineIdx) {
				continue
			}

		case "918": // SSRF
			// No HTTP request in this line — suppress misidentified patterns
			if !pyHasHTTPCall(lines, lineIdx) {
				continue
			}

		case "78": // Command injection
			// subprocess with list args and shell=False is safe
			if pyIsSubprocessSafe(lines, lineIdx) {
				continue
			}
		}

		kept = append(kept, f)
	}
	return kept
}

// File-level pattern detectors.
var (
	pyHasSQLAlchemyORM = regexp.MustCompile(`(?i)(?:from\s+sqlalchemy|select\s*\(|\.query\s*\()`)
	pyHasDjangoORM     = regexp.MustCompile(`(?i)(?:from\s+django|\.objects\.)`)
	pyHasJWTEncode     = regexp.MustCompile(`(?i)jwt\.encode\s*\(`)
	pyHasPydantic      = regexp.MustCompile(`(?i)(?:from\s+pydantic|BaseModel)`)
)

// pyIsSQLAlchemyQuery checks if the finding line uses SQLAlchemy ORM patterns
// which are parameterized by design.
func pyIsSQLAlchemyQuery(lines []string, lineIdx int) bool {
	start := lineIdx - 3
	if start < 0 {
		start = 0
	}
	end := lineIdx + 3
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		if pySQLAlchemySafe.MatchString(line) {
			return true
		}
	}
	return false
}

var pySQLAlchemySafe = regexp.MustCompile(`(?i)(?:` +
	`select\s*\(\s*\w+\s*\)\.where|` + // select(Model).where(...)
	`\.filter\s*\(|` + // .filter(...)
	`\.filter_by\s*\(|` + // .filter_by(...)
	`\.query\s*\.\s*(?:filter|get|first|all)|` + // session.query.filter()
	`db\.execute\s*\(\s*(?:select|insert|update|delete)\s*\(|` + // db.execute(select(...))
	`text\s*\(\s*["'][^"']*["']\s*\)\s*,\s*\{` + // text("..."), {params}
	`)`)

// pyIsDjangoQuery checks for Django ORM patterns.
func pyIsDjangoQuery(lines []string, lineIdx int) bool {
	start := lineIdx - 2
	if start < 0 {
		start = 0
	}
	end := lineIdx + 2
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		if pyDjangoSafe.MatchString(line) {
			return true
		}
	}
	return false
}

var pyDjangoSafe = regexp.MustCompile(`(?i)\.objects\.(?:filter|get|exclude|create|update|annotate|aggregate)\s*\(`)

// pyIsJWTEncode checks if the finding line is jwt.encode (not a file write).
func pyIsJWTEncode(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	// Check the finding line and nearby lines for jwt.encode
	start := lineIdx - 2
	if start < 0 {
		start = 0
	}
	end := lineIdx + 2
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		if strings.Contains(line, "jwt.encode") || strings.Contains(line, "jwt.decode") {
			return true
		}
	}
	return false
}

// pyIsPydanticValidation checks for Pydantic model validation (safe deser).
func pyIsPydanticValidation(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	start := lineIdx - 2
	if start < 0 {
		start = 0
	}
	end := lineIdx + 2
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		if pyPydanticSafe.MatchString(line) {
			return true
		}
	}
	return false
}

var pyPydanticSafe = regexp.MustCompile(`(?i)(?:` +
	`\w+Model\s*\(|` + // SomeModel(...)
	`\.model_validate\s*\(|` + // Model.model_validate(...)
	`\.parse_obj\s*\(|` + // Model.parse_obj(...)
	`\.parse_raw\s*\(|` + // Model.parse_raw(...)
	`BaseModel` + // class X(BaseModel)
	`)`)

// pyIsSafeJSONParse checks for json.loads with typed assignment.
func pyIsSafeJSONParse(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	line := lines[lineIdx]
	// json.loads(...) assigned to a typed variable with validation
	return strings.Contains(line, "json.loads") && !strings.Contains(line, "eval") && !strings.Contains(line, "exec")
}

// pyHasHTTPCall checks if the line or nearby lines have actual HTTP calls.
func pyHasHTTPCall(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	start := lineIdx - 3
	if start < 0 {
		start = 0
	}
	end := lineIdx + 3
	if end > len(lines) {
		end = len(lines)
	}
	for _, line := range lines[start:end] {
		if pyHTTPCall.MatchString(line) {
			return true
		}
	}
	return false
}

var pyHTTPCall = regexp.MustCompile(`(?i)(?:` +
	`requests\.(?:get|post|put|delete|patch|head)\s*\(|` +
	`httpx\.(?:get|post|put|delete)\s*\(|` +
	`urllib\.request\.urlopen\s*\(|` +
	`aiohttp\.ClientSession|` +
	`fetch\s*\(` +
	`)`)

// pyIsSubprocessSafe checks for safe subprocess patterns (list args, no shell).
func pyIsSubprocessSafe(lines []string, lineIdx int) bool {
	if lineIdx < 0 || lineIdx >= len(lines) {
		return false
	}
	start := lineIdx - 5
	if start < 0 {
		start = 0
	}
	end := lineIdx + 5
	if end > len(lines) {
		end = len(lines)
	}
	hasListArgs := false
	hasShellFalse := false
	for _, line := range lines[start:end] {
		if strings.Contains(line, "subprocess.run") || strings.Contains(line, "subprocess.Popen") || strings.Contains(line, "subprocess.call") {
			// Check for list argument: subprocess.run(["cmd", ...])
			if strings.Contains(line, "[") {
				hasListArgs = true
			}
		}
		if strings.Contains(line, "shell=False") || strings.Contains(line, "shell = False") {
			hasShellFalse = true
		}
	}
	// List args with no shell=True is safe (shell defaults to False)
	if hasListArgs {
		hasShellTrue := false
		for _, line := range lines[start:end] {
			if strings.Contains(line, "shell=True") || strings.Contains(line, "shell = True") {
				hasShellTrue = true
			}
		}
		return !hasShellTrue || hasShellFalse
	}
	return false
}
