package traversal

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// --- Compiled patterns ---

// BATOU-TRV-001: Path Traversal
var (
	// Go: os.Open/ReadFile/etc with variable (not string literal)
	goFileOpUserInput = regexp.MustCompile(`\b(?:os\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|Stat|Lstat|Mkdir|MkdirAll)|ioutil\.ReadFile)\s*\(\s*[a-zA-Z_]\w*`)
	// Go: filepath.Join without subsequent Clean+prefix check
	goFilepathJoin = regexp.MustCompile(`filepath\.Join\s*\(`)
	// Python: open() with variable from request/user input
	pyOpenUserInput = regexp.MustCompile(`\bopen\s*\(\s*(?:request\.(?:args|form|values|GET|POST)\s*\[|user_input|filename|file_path|path|f?name)`)
	// Python: os.path.join with user input
	pyOsPathJoin = regexp.MustCompile(`os\.path\.join\s*\([^)]*(?:request\.|user_input|input|param|arg)`)
	// JS/TS: fs operations with req.query/req.params/req.body
	jsFileOpUserInput = regexp.MustCompile(`\bfs\.\w+(?:Sync)?\s*\(\s*(?:req\.(?:query|params|body|param)\s*[\[.]|userInput|filePath|fileName|inputPath)`)
	// PHP: file operations with user input
	phpFileOpUserInput = regexp.MustCompile(`\b(?:file_get_contents|file_put_contents|fopen|readfile|file)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_FILES|input|param|path|file)`)
	// Ruby: send_file / File.read / File.join with params or user variable
	rubyFileOpUserInput = regexp.MustCompile(`\b(?:send_file|File\.(?:read|open|join|new|write|binread))\s*[\(]?\s*(?:params\s*\[|File\.join\s*\(|Rails\.root\.join)`)
	// Ruby: File.read/open with string interpolation from params
	rubyFileInterpolation = regexp.MustCompile(`\bFile\.(?:read|open|binread)\s*\(\s*["'][^"']*#\{`)
	// C: fopen/fread/open with variable (not string literal)
	cFileOpUserInput = regexp.MustCompile(`\b(?:fopen|fread|fwrite|open|freopen|fdopen|tmpfile|remove|rename)\s*\(\s*[a-zA-Z_]\w*`)
	// Generic ../
	dotDotSlashInVar = regexp.MustCompile(`(?:["']\s*\+\s*|["']?\s*\.\.\s*/|\.\.\\\\)`)
)

// BATOU-TRV-002: File Inclusion
var (
	phpDynamicInclude    = regexp.MustCompile(`\b(?:include|require|include_once|require_once)\s*[\(]?\s*\$`)
	pyDynamicImport      = regexp.MustCompile(`\b(?:__import__|importlib\.import_module)\s*\(\s*[a-zA-Z_]\w*`)
	rubyDynamicLoadReq   = regexp.MustCompile(`\b(?:load|require)\s*[\(]?\s*[a-zA-Z_]\w*`)
)

// BATOU-TRV-003: Archive Extraction (Zip Slip / Tar Slip)
var (
	// Go: zip.OpenReader / zip.NewReader extraction without path checking
	goZipExtract = regexp.MustCompile(`(?:zip\.(?:OpenReader|NewReader)|archive/zip)`)
	goZipFile    = regexp.MustCompile(`\.Open\(\)`)
	// Python: extractall without members filter
	pyExtractAll = regexp.MustCompile(`\.(?:extractall|extract)\s*\(`)
	// Python: zipfile/tarfile import context
	pyArchiveImport = regexp.MustCompile(`\b(?:zipfile|tarfile)\b`)
	// JS: unzip/extract patterns
	jsUnzipExtract = regexp.MustCompile(`\b(?:unzip|extract|decompress)\s*\(`)
	// Go: os.Create with path from zip entry
	goCreateFromZip = regexp.MustCompile(`os\.Create\s*\(\s*(?:filepath\.Join|path\.Join|name|entry\.Name|header\.Name|f\.Name)`)
)

// BATOU-TRV-004: Symlink Following
var (
	goReadlink    = regexp.MustCompile(`os\.Readlink\s*\(`)
	goLstat       = regexp.MustCompile(`os\.Lstat\s*\(`)
	goEvalSymlink = regexp.MustCompile(`filepath\.EvalSymlinks\s*\(`)
)

// BATOU-TRV-005: Template Path Injection
var (
	// JS/TS: res.render(variable) where first arg is not a string literal
	jsResRender = regexp.MustCompile(`\bres\.render\s*\(\s*[a-zA-Z_]\w*`)
	// Python: render_template(variable) where first arg is not a string literal
	pyRenderTemplate = regexp.MustCompile(`\brender_template\s*\(\s*[a-zA-Z_]\w*`)
	// Generic: render(variable) — catches Express/Flask patterns
	genericRender = regexp.MustCompile(`\brender\s*\(\s*[a-zA-Z_]\w*`)
)

// BATOU-TRV-006: Prototype Pollution via Spread
var (
	// JS/TS: { ...req.body } spread operator
	jsSpreadReqBody = regexp.MustCompile(`\{\s*\.\.\.req\.body\b`)
	// JS/TS: Object.assign({}, req.body)
	jsObjectAssignReqBody = regexp.MustCompile(`Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.body\b`)
)

// BATOU-TRV-007: Express sendFile/download with Variable Path
var (
	// JS/TS: res.sendFile(variable) — not a string literal
	jsSendFile = regexp.MustCompile(`\bres\.sendFile\s*\(\s*[a-zA-Z_]\w*`)
	// JS/TS: res.download(variable) — not a string literal
	jsDownload = regexp.MustCompile(`\bres\.download\s*\(\s*[a-zA-Z_]\w*`)
)

// BATOU-TRV-008: Null Byte in File Path
var (
	// File operations with user input variables but no null byte sanitization
	nullByteFileOp = regexp.MustCompile(`(?:open|readFile|readFileSync|createReadStream|sendFile|download|ReadFile|Open|OpenFile)\s*\(\s*[a-zA-Z_]\w*`)
)

// BATOU-TRV-009: Express Render Options Injection (layout override via spread)
var (
	// JS/TS: res.render('template', { ...req.body }) or res.render('template', { ...req.body, ... })
	jsRenderSpreadBody = regexp.MustCompile(`\bres\.render\s*\([^,]+,\s*\{[^}]*\.\.\.req\.body\b`)
	// JS/TS: res.render('template', Object.assign({}, req.body))
	jsRenderAssignBody = regexp.MustCompile(`\bres\.render\s*\([^,]+,\s*Object\.assign\s*\([^)]*req\.body\b`)
	// JS/TS: res.render(anything, { ...req.query }) or { ...req.params }
	jsRenderSpreadReq = regexp.MustCompile(`\bres\.render\s*\([^,]+,\s*\{[^}]*\.\.\.req\.(?:query|params)\b`)
)

// BATOU-TRV-010: Zip Slip Path Traversal
var (
	// Go: zip.File.Name or header.Name used in filepath.Join/os.Create without path check
	goZipSlipJoinCreate = regexp.MustCompile(`(?:filepath\.Join|os\.Create|os\.OpenFile|os\.MkdirAll)\s*\([^)]*(?:\.Name\b|entry\.Name|header\.Name|f\.Name|file\.Name|zipEntry|zf\.Name)`)
	// Go: zip.File range with file operations
	goZipSlipRange = regexp.MustCompile(`for\s+.*range\s+.*\.File\b`)
	// Java: ZipEntry.getName() used in new File() without validation
	javaZipSlipNewFile = regexp.MustCompile(`new\s+File\s*\([^)]*(?:\.getName\s*\(\)|entry\.getName|zipEntry\.getName)`)
	// Java: ZipEntry.getName() used in path construction
	javaZipSlipPath = regexp.MustCompile(`(?:Paths\.get|Path\.of|resolve)\s*\([^)]*(?:\.getName\s*\(\)|entry\.getName|zipEntry\.getName)`)
	// Python: tarfile.extractall() without members filter
	pyTarExtractAll = regexp.MustCompile(`tarfile\.open\b.*\.extractall\s*\(`)
	// Python: tarfile extraction without safe filter
	pyTarExtract = regexp.MustCompile(`\.extractall\s*\([^)]*\)`)
	// Python: tarfile import + extractall
	pyTarImport = regexp.MustCompile(`\btarfile\b`)
	// Python: manual zip extract with path join
	pyZipSlipManual = regexp.MustCompile(`os\.path\.join\s*\([^)]*\.(?:filename|name)\b`)
	// JS: zip entry path used in createWriteStream/writeFile without validation
	jsZipSlipWrite = regexp.MustCompile(`(?:fs\.createWriteStream|fs\.writeFile|fs\.writeFileSync)\s*\([^)]*(?:entry\.(?:fileName|path|name)|file\.(?:path|name)|zipEntry)`)
	// JS: adm-zip/yauzl/unzipper entry path in file operations
	jsZipSlipEntry = regexp.MustCompile(`(?:path\.join|path\.resolve)\s*\([^)]*(?:entry\.(?:fileName|path|name)|file\.(?:path|name)|zipEntry\.(?:fileName|path))`)
)

func init() {
	rules.Register(&PathTraversal{})
	rules.Register(&FileInclusion{})
	rules.Register(&ArchiveExtraction{})
	rules.Register(&SymlinkFollowing{})
	rules.Register(&TemplatePathInjection{})
	rules.Register(&PrototypePollution{})
	rules.Register(&ExpressSendFilePath{})
	rules.Register(&NullByteFilePath{})
	rules.Register(&RenderOptionsInjection{})
	rules.Register(&ZipSlipTraversal{})
}

// --- BATOU-TRV-001: Path Traversal ---

type PathTraversal struct{}

func (r *PathTraversal) ID() string             { return "BATOU-TRV-001" }
func (r *PathTraversal) Name() string            { return "PathTraversal" }
func (r *PathTraversal) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *PathTraversal) Description() string {
	return "Detects file operations using unsanitized user input that may allow path traversal (../) attacks."
}

func (r *PathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if isComment(trimmed) {
			continue
		}

		var matched string

		switch ctx.Language {
		case rules.LangGo:
			if loc := goFileOpUserInput.FindString(line); loc != "" {
				// Check if the line also has filepath.Clean + strings.HasPrefix nearby
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
			if matched == "" {
				if loc := goFilepathJoin.FindString(line); loc != "" {
					if !hasTraversalGuard(lines, i) {
						matched = strings.TrimSpace(line)
					}
				}
			}
		case rules.LangPython:
			if loc := pyOpenUserInput.FindString(line); loc != "" {
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
			if matched == "" {
				if loc := pyOsPathJoin.FindString(line); loc != "" {
					if !hasTraversalGuard(lines, i) {
						matched = loc
					}
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := jsFileOpUserInput.FindString(line); loc != "" {
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
		case rules.LangPHP:
			if loc := phpFileOpUserInput.FindString(line); loc != "" {
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
		case rules.LangRuby:
			if loc := rubyFileOpUserInput.FindString(line); loc != "" {
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
			if matched == "" {
				if loc := rubyFileInterpolation.FindString(line); loc != "" {
					if !hasTraversalGuard(lines, i) {
						matched = loc
					}
				}
			}
		case rules.LangC:
			if loc := cFileOpUserInput.FindString(line); loc != "" {
				// Only flag if argument is a variable, not a string literal
				afterMatch := line[strings.Index(line, loc)+len(loc):]
				_ = afterMatch
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
		default:
			// For any language, check for obvious traversal patterns
			if loc := dotDotSlashInVar.FindString(line); loc != "" {
				// Only flag if also doing file I/O
				if strings.Contains(line, "open") || strings.Contains(line, "read") ||
					strings.Contains(line, "write") || strings.Contains(line, "file") ||
					strings.Contains(line, "path") || strings.Contains(line, "include") {
					if !hasTraversalGuard(lines, i) {
						matched = strings.TrimSpace(line)
					}
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Potential path traversal via unsanitized input",
				Description:   "File operation uses potentially user-controlled input without path sanitization. An attacker could use '../' sequences to access files outside the intended directory.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Sanitize paths with filepath.Clean (Go), os.path.realpath (Python), or path.resolve (JS), then verify the result starts with the expected base directory.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "medium",
				Tags:          []string{"traversal", "path-traversal", "file-access"},
			})
		}
	}

	return findings
}

// hasTraversalGuard checks the enclosing function scope for path traversal guards.
// It recognises two categories of guard:
//  1. Standalone guards that are sufficient on their own (e.g. filepath.Base, basename()).
//  2. Multi-step guards: a normalisation call (filepath.Clean, realpath, path.resolve, etc.)
//     combined with a containment check (strings.HasPrefix, .startsWith, str_starts_with, etc.).
//
// It also recognises allowlist patterns (allowed[, in_array, .includes()) as guards.
func hasTraversalGuard(lines []string, idx int) bool {
	start, end := functionScope(lines, idx)

	for _, l := range lines[start:end] {
		// --- Category 1: Standalone basename guard ---
		// filepath.Base / os.path.basename / path.basename / basename() strip
		// all directory components, which is sufficient to prevent traversal.
		if strings.Contains(l, "filepath.Base(") ||
			strings.Contains(l, "os.path.basename(") ||
			strings.Contains(l, "path.basename(") ||
			(strings.Contains(l, "basename(") && !strings.Contains(l, "os.path.basename")) {
			return true
		}

		// --- Category 1: Allowlist guard ---
		// If the function checks against an allowlist, traversal is not possible.
		if isAllowlistGuard(l) {
			return true
		}
	}

	// --- Category 2: Multi-step normalise + containment guard ---
	hasNormalise := false
	hasContainment := false

	for _, l := range lines[start:end] {
		// Normalisation patterns (any language).
		if strings.Contains(l, "filepath.Clean") || strings.Contains(l, "filepath.Abs") ||
			strings.Contains(l, "path.Clean") || strings.Contains(l, "filepath.EvalSymlinks") ||
			strings.Contains(l, "os.path.realpath") || strings.Contains(l, "os.path.abspath") ||
			strings.Contains(l, ".resolve(") || // Python pathlib .resolve() and JS path.resolve()
			strings.Contains(l, "path.resolve") ||
			strings.Contains(l, ".normalize()") ||
			strings.Contains(l, ".toRealPath()") || strings.Contains(l, ".getCanonicalPath()") ||
			strings.Contains(l, "File.realpath") ||   // Ruby
			strings.Contains(l, "File.expand_path") || // Ruby
			strings.Contains(l, "realpath(") {         // PHP realpath()
			hasNormalise = true
		}

		// Containment / prefix-check patterns (any language).
		if strings.Contains(l, "strings.HasPrefix") ||
			strings.Contains(l, "strings.Contains") ||
			strings.Contains(l, ".startswith(") ||     // Python
			strings.Contains(l, ".startsWith(") ||     // JS/Java
			strings.Contains(l, ".start_with?(") ||    // Ruby
			strings.Contains(l, "str_starts_with(") || // PHP 8+
			(strings.Contains(l, "strpos(") && strings.Contains(l, "===")) || // PHP strpos check
			strings.Contains(l, ".includes('..')") ||  // JS ..check
			strings.Contains(l, `".."`) && (strings.Contains(l, "Contains") || strings.Contains(l, "contains")) {
			hasContainment = true
		}
	}

	return hasNormalise && hasContainment
}

// functionScope returns the start and end indices (half-open) of the function
// enclosing the line at idx, by scanning for function boundaries. If no clear
// function boundary is found, it falls back to a generous +/-40 line window.
func functionScope(lines []string, idx int) (int, int) {
	// Scan backward for function start. We begin one line above idx
	// so that braces on the flagged line itself don't confuse the scan.
	start := 0
	braceDepth := 0
	for i := idx - 1; i >= 0; i-- {
		l := lines[i]
		braceDepth += strings.Count(l, "}") - strings.Count(l, "{")
		if braceDepth < 0 {
			// We've exited the enclosing block upward — the function
			// starts at or just after this line.
			start = i
			break
		}
		// Language-specific function declarations.
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "func ") || // Go
			strings.HasPrefix(trimmed, "def ") || // Python/Ruby
			strings.HasPrefix(trimmed, "function ") || // JS/PHP
			strings.Contains(trimmed, "function(") || // JS anonymous
			strings.Contains(trimmed, "=> {") || // JS arrow
			strings.Contains(trimmed, "=>{") { // JS arrow compact
			start = i
			break
		}
	}

	// Scan forward for function end. Start one line after idx to avoid
	// the flagged line's braces.
	end := len(lines)
	braceDepth = 0
	for i := idx + 1; i < len(lines); i++ {
		l := lines[i]
		braceDepth += strings.Count(l, "{") - strings.Count(l, "}")
		if braceDepth < 0 {
			end = i + 1
			break
		}
	}

	// For languages without braces (Python), use indentation as a fallback.
	// If we didn't find clear boundaries, use a generous window.
	if end-start < 3 {
		fallbackStart := idx - 40
		if fallbackStart < 0 {
			fallbackStart = 0
		}
		fallbackEnd := idx + 40
		if fallbackEnd > len(lines) {
			fallbackEnd = len(lines)
		}
		if fallbackStart < start {
			start = fallbackStart
		}
		if fallbackEnd > end {
			end = fallbackEnd
		}
	}

	return start, end
}

// isAllowlistGuard returns true if the line contains an allowlist check pattern.
func isAllowlistGuard(line string) bool {
	// Go: map lookup like allowed[name]
	if strings.Contains(line, "allowed[") || strings.Contains(line, "whitelist[") ||
		strings.Contains(line, "allowlist[") || strings.Contains(line, "permitted[") {
		return true
	}
	// PHP: in_array
	if strings.Contains(line, "in_array(") {
		return true
	}
	// JS: .includes( for array membership
	if strings.Contains(line, ".includes(") && !strings.Contains(line, "'..'") && !strings.Contains(line, `".."`) {
		return true
	}
	// Python: in allowed / in whitelist
	if (strings.Contains(line, " in ") || strings.Contains(line, " not in ")) &&
		(strings.Contains(line, "allowed") || strings.Contains(line, "whitelist") ||
			strings.Contains(line, "ALLOWED") || strings.Contains(line, "allowlist")) {
		return true
	}
	return false
}

// --- BATOU-TRV-002: File Inclusion ---

type FileInclusion struct{}

func (r *FileInclusion) ID() string             { return "BATOU-TRV-002" }
func (r *FileInclusion) Name() string            { return "FileInclusion" }
func (r *FileInclusion) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *FileInclusion) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP, rules.LangPython, rules.LangRuby}
}

func (r *FileInclusion) Description() string {
	return "Detects local/remote file inclusion vulnerabilities where dynamic user input controls included file paths."
}

func (r *FileInclusion) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var desc string

		switch ctx.Language {
		case rules.LangPHP:
			if loc := phpDynamicInclude.FindString(line); loc != "" {
				if !hasPHPIncludeGuard(lines, i) {
					matched = loc
					desc = "PHP include/require with dynamic variable. An attacker may control the included file path, leading to Local File Inclusion (LFI) or Remote File Inclusion (RFI)."
				}
			}
		case rules.LangPython:
			if loc := pyDynamicImport.FindString(line); loc != "" {
				matched = loc
				desc = "Dynamic Python import with variable input. An attacker may load arbitrary modules if the input is user-controlled."
			}
		case rules.LangRuby:
			if loc := rubyDynamicLoadReq.FindString(line); loc != "" {
				// Avoid false positives on require with string literals
				if !strings.Contains(line, `require "`) && !strings.Contains(line, `require '`) &&
					!strings.Contains(line, `load "`) && !strings.Contains(line, `load '`) {
					matched = loc
					desc = "Ruby load/require with dynamic variable. An attacker may load arbitrary files if the input is user-controlled."
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Dynamic file inclusion with variable input",
				Description:   desc,
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a whitelist of allowed files/modules instead of dynamic inclusion. Never pass user input directly to include/require.",
				CWEID:         "CWE-98",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"traversal", "file-inclusion", "lfi", "rfi"},
			})
		}
	}

	return findings
}

// hasPHPIncludeGuard checks if the PHP include/require has a guard like
// array_key_exists, in_array, allowlist check, or path sanitization nearby.
func hasPHPIncludeGuard(lines []string, idx int) bool {
	start := idx - 15
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if strings.Contains(l, "array_key_exists") || strings.Contains(l, "in_array") ||
			strings.Contains(l, "preg_replace") || strings.Contains(l, "preg_match") ||
			strings.Contains(l, "basename(") || strings.Contains(l, "realpath(") ||
			(strings.Contains(l, "strpos") && strings.Contains(l, "===")) {
			return true
		}
	}
	return false
}

// --- BATOU-TRV-003: Archive Extraction ---

type ArchiveExtraction struct{}

func (r *ArchiveExtraction) ID() string             { return "BATOU-TRV-003" }
func (r *ArchiveExtraction) Name() string            { return "ArchiveExtraction" }
func (r *ArchiveExtraction) DefaultSeverity() rules.Severity { return rules.High }
func (r *ArchiveExtraction) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *ArchiveExtraction) Description() string {
	return "Detects archive extraction (zip/tar) without path validation, which may allow zip-slip attacks to write files outside the target directory."
}

func (r *ArchiveExtraction) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string

		switch ctx.Language {
		case rules.LangGo:
			// Check for os.Create with paths from zip/tar entries without validation
			if loc := goCreateFromZip.FindString(line); loc != "" {
				if !hasTraversalGuard(lines, i) {
					matched = loc
					confidence = "medium"
				}
			}
			// Check for zip extraction patterns
			if matched == "" && goZipExtract.MatchString(line) {
				// Only flag if there's no path validation in context
				if !hasZipSlipGuard(lines) {
					matched = strings.TrimSpace(line)
					confidence = "low"
				}
			}
		case rules.LangPython:
			if loc := pyExtractAll.FindString(line); loc != "" {
				// Check if it has members= parameter (safe)
				if !strings.Contains(line, "members=") && !strings.Contains(line, "members =") {
					matched = strings.TrimSpace(line)
					confidence = "high"
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := jsUnzipExtract.FindString(line); loc != "" {
				matched = strings.TrimSpace(line)
				confidence = "medium"
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Archive extraction without path validation (zip-slip risk)",
				Description:   "Archive entries may contain '../' in their paths, allowing files to be extracted outside the intended directory (zip-slip attack).",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate that extracted file paths resolve within the target directory. In Python, use the members parameter or check each entry. In Go, use filepath.Clean and strings.HasPrefix.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    confidence,
				Tags:          []string{"traversal", "zip-slip", "archive"},
			})
		}
	}

	return findings
}

// hasZipSlipGuard checks the entire file for zip-slip mitigation patterns.
func hasZipSlipGuard(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "strings.HasPrefix") && strings.Contains(l, "filepath.Clean") {
			return true
		}
		if strings.Contains(l, `"../"`) || strings.Contains(l, `'..'`) {
			// Checking for traversal patterns suggests awareness
			if strings.Contains(l, "if") || strings.Contains(l, "err") {
				return true
			}
		}
	}
	return false
}

// --- BATOU-TRV-004: Symlink Following ---

type SymlinkFollowing struct{}

func (r *SymlinkFollowing) ID() string             { return "BATOU-TRV-004" }
func (r *SymlinkFollowing) Name() string            { return "SymlinkFollowing" }
func (r *SymlinkFollowing) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SymlinkFollowing) Languages() []rules.Language {
	return []rules.Language{rules.LangGo}
}

func (r *SymlinkFollowing) Description() string {
	return "Detects code that follows symlinks without validation in security-sensitive file operations, which may allow symlink-based attacks."
}

func (r *SymlinkFollowing) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Track if Readlink is used and whether validation follows
	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		if goReadlink.MatchString(line) {
			// Check if subsequent lines validate the resolved path
			hasValidation := false
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			for _, subsequent := range lines[i+1 : end] {
				if strings.Contains(subsequent, "strings.HasPrefix") ||
					strings.Contains(subsequent, "filepath.Clean") ||
					strings.Contains(subsequent, "filepath.Abs") ||
					strings.Contains(subsequent, "filepath.EvalSymlinks") {
					hasValidation = true
					break
				}
			}
			if !hasValidation {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "Symlink resolution without path validation",
					Description:   "os.Readlink resolves a symlink target but the result is not validated before use. An attacker who controls the symlink could redirect file operations to arbitrary paths.",
					LineNumber:    lineNum,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "After resolving symlinks, validate the result with filepath.Clean and strings.HasPrefix to ensure it stays within the expected directory.",
					CWEID:         "CWE-22",
					OWASPCategory: "A01:2021-Broken Access Control",
					Confidence:    "medium",
					Tags:          []string{"traversal", "symlink", "toctou"},
				})
			}
		}
	}

	return findings
}

// --- BATOU-TRV-005: Template Path Injection ---

type TemplatePathInjection struct{}

func (r *TemplatePathInjection) ID() string             { return "BATOU-TRV-005" }
func (r *TemplatePathInjection) Name() string            { return "TemplatePathInjection" }
func (r *TemplatePathInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *TemplatePathInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython}
}

func (r *TemplatePathInjection) Description() string {
	return "Detects template rendering where the template name/path comes from user-controlled input, allowing an attacker to read arbitrary files via template engine path traversal."
}

func (r *TemplatePathInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string

		switch ctx.Language {
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := jsResRender.FindString(line); loc != "" {
				// Skip if arg is a string literal
				if !isStringLiteralArg(line, "render") {
					matched = loc
				}
			}
		case rules.LangPython:
			if loc := pyRenderTemplate.FindString(line); loc != "" {
				if !isStringLiteralArg(line, "render_template") {
					matched = loc
				}
			}
		}

		// Fallback for generic render() across supported languages
		if matched == "" {
			if loc := genericRender.FindString(line); loc != "" {
				if !isStringLiteralArg(line, "render") &&
					(ctx.Language == rules.LangJavaScript || ctx.Language == rules.LangTypeScript || ctx.Language == rules.LangPython) {
					matched = loc
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Template path controlled by user input",
				Description:   "Template rendering uses a variable (not a string literal) as the template name. If this value originates from user input, an attacker can traverse the file system and read arbitrary files via the template engine.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Use a whitelist of allowed template names. Never pass user input directly as the template path to res.render() or render_template().",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "medium",
				Tags:          []string{"traversal", "template-injection", "local-file-read"},
			})
		}
	}

	return findings
}

// --- BATOU-TRV-006: Prototype Pollution via Spread ---

type PrototypePollution struct{}

func (r *PrototypePollution) ID() string             { return "BATOU-TRV-006" }
func (r *PrototypePollution) Name() string            { return "PrototypePollution" }
func (r *PrototypePollution) DefaultSeverity() rules.Severity { return rules.High }
func (r *PrototypePollution) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *PrototypePollution) Description() string {
	return "Detects spreading or merging of req.body into objects, which allows attackers to inject arbitrary properties (mass assignment / prototype pollution)."
}

func (r *PrototypePollution) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string

		if loc := jsSpreadReqBody.FindString(line); loc != "" {
			matched = loc
		}
		if matched == "" {
			if loc := jsObjectAssignReqBody.FindString(line); loc != "" {
				matched = loc
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Mass assignment via request body spread/merge",
				Description:   "Spreading or Object.assign of req.body into an object allows an attacker to inject unexpected properties. For example, { ...req.body } lets an attacker control any property including 'layout', '__proto__', or 'isAdmin'.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Destructure only the expected fields from req.body: const { name, email } = req.body. Never spread the entire request body into objects.",
				CWEID:         "CWE-915",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"mass-assignment", "prototype-pollution", "request-body"},
			})
		}
	}

	return findings
}

// --- BATOU-TRV-007: Express sendFile/download with Variable Path ---

type ExpressSendFilePath struct{}

func (r *ExpressSendFilePath) ID() string             { return "BATOU-TRV-007" }
func (r *ExpressSendFilePath) Name() string            { return "ExpressSendFilePath" }
func (r *ExpressSendFilePath) DefaultSeverity() rules.Severity { return rules.High }
func (r *ExpressSendFilePath) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ExpressSendFilePath) Description() string {
	return "Detects Express res.sendFile() or res.download() with a variable path argument, which may allow path traversal to serve arbitrary files."
}

func (r *ExpressSendFilePath) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string

		if loc := jsSendFile.FindString(line); loc != "" {
			if !hasTraversalGuard(lines, i) {
				matched = loc
			}
		}
		if matched == "" {
			if loc := jsDownload.FindString(line); loc != "" {
				if !hasTraversalGuard(lines, i) {
					matched = loc
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "File serving with user-controlled path",
				Description:   "res.sendFile() or res.download() uses a variable path without visible path sanitization. An attacker could use path traversal to download arbitrary files from the server.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Resolve the path with path.resolve() and verify it starts with the intended base directory using a prefix check. Use the root option in res.sendFile() to restrict the base directory.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "medium",
				Tags:          []string{"traversal", "file-download", "express"},
			})
		}
	}

	return findings
}

// --- BATOU-TRV-008: Null Byte in File Path ---

type NullByteFilePath struct{}

func (r *NullByteFilePath) ID() string             { return "BATOU-TRV-008" }
func (r *NullByteFilePath) Name() string            { return "NullByteFilePath" }
func (r *NullByteFilePath) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *NullByteFilePath) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *NullByteFilePath) Description() string {
	return "Detects file operations with user-controlled paths that lack null byte sanitization. Null bytes can truncate file paths in some runtimes, bypassing extension checks."
}

func (r *NullByteFilePath) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// First check if the file already has null byte sanitization in non-comment code
	hasNullByteSanitizer := false
	for _, l := range lines {
		trimmedL := strings.TrimSpace(l)
		// Skip comment lines when checking for sanitizers
		if isComment(trimmedL) {
			continue
		}
		if strings.Contains(l, `\0`) || strings.Contains(l, `\x00`) ||
			strings.Contains(l, "cutOffPoisonNullByte") ||
			strings.Contains(l, "nullbyte") || strings.Contains(l, "NullByte") {
			hasNullByteSanitizer = true
			break
		}
	}

	if hasNullByteSanitizer {
		return findings
	}

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		if loc := nullByteFileOp.FindString(line); loc != "" {
			// Only flag if user input indicators are present nearby
			if hasUserInputIndicator(lines, i) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					Title:         "File operation without null byte sanitization",
					Description:   "File path operation uses a variable that may contain user input, but no null byte sanitization was found in the file. A null byte (\\x00) can truncate the path in some runtimes, bypassing file extension checks.",
					LineNumber:    lineNum,
					MatchedText:   truncate(loc, 120),
					Suggestion:    "Strip null bytes from user-supplied paths: path.replace(/\\0/g, '') in JS, or use a dedicated sanitizer like cutOffPoisonNullByte before file operations.",
					CWEID:         "CWE-159",
					OWASPCategory: "A01:2021-Broken Access Control",
					Confidence:    "low",
					Tags:          []string{"traversal", "null-byte", "file-access"},
				})
			}
		}
	}

	return findings
}

// hasUserInputIndicator checks surrounding lines for user input patterns (req.*, params, etc.)
func hasUserInputIndicator(lines []string, idx int) bool {
	start := idx - 10
	if start < 0 {
		start = 0
	}
	end := idx + 5
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if strings.Contains(l, "req.") || strings.Contains(l, "request.") ||
			strings.Contains(l, "params") || strings.Contains(l, "user_input") ||
			strings.Contains(l, "query") || strings.Contains(l, "body") {
			return true
		}
	}
	return false
}

// --- BATOU-TRV-009: Express Render Options Injection ---

type RenderOptionsInjection struct{}

func (r *RenderOptionsInjection) ID() string             { return "BATOU-TRV-009" }
func (r *RenderOptionsInjection) Name() string            { return "RenderOptionsInjection" }
func (r *RenderOptionsInjection) DefaultSeverity() rules.Severity { return rules.High }
func (r *RenderOptionsInjection) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *RenderOptionsInjection) Description() string {
	return "Detects Express res.render() where user input (req.body/req.query/req.params) is spread into the render options object. An attacker can override the 'layout' property to control which template file is used as the layout, enabling local file read via the template engine."
}

func (r *RenderOptionsInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Use a sliding window of up to 5 lines to detect patterns that span
	// multiple lines (e.g., res.render('tpl', {\n  ...req.body\n})).
	const windowSize = 5

	for i := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(lines[i])

		if isComment(trimmed) {
			continue
		}

		// Build a joined window from lines[i..i+windowSize).
		end := i + windowSize
		if end > len(lines) {
			end = len(lines)
		}
		window := strings.Join(lines[i:end], " ")

		var matched string

		if loc := jsRenderSpreadBody.FindString(window); loc != "" {
			matched = loc
		}
		if matched == "" {
			if loc := jsRenderAssignBody.FindString(window); loc != "" {
				matched = loc
			}
		}
		if matched == "" {
			if loc := jsRenderSpreadReq.FindString(window); loc != "" {
				matched = loc
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "User input spread into Express render options (layout override)",
				Description:   "res.render() receives user-controlled data (req.body/req.query/req.params) spread into the options object. An attacker can inject a 'layout' property to override the Express layout template path, enabling local file read (LFR) through the template engine. This is the pattern used in OWASP Juice Shop's dataErasure vulnerability.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Never spread req.body/req.query/req.params into render options. Destructure only the expected fields: const { field1, field2 } = req.body; res.render('template', { field1, field2 }).",
				CWEID:         "CWE-94",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    "high",
				Tags:          []string{"traversal", "layout-injection", "express", "local-file-read", "mass-assignment"},
			})
		}
	}

	return findings
}

// isStringLiteralArg checks if the first argument to a function call is a string literal.
func isStringLiteralArg(line, funcName string) bool {
	idx := strings.Index(line, funcName+"(")
	if idx == -1 {
		idx = strings.Index(line, funcName+" (")
	}
	if idx == -1 {
		return false
	}
	after := line[idx+len(funcName):]
	after = strings.TrimLeft(after, " \t(")
	return strings.HasPrefix(after, `"`) || strings.HasPrefix(after, `'`) || strings.HasPrefix(after, "`")
}

// --- BATOU-TRV-010: Zip Slip Path Traversal ---

type ZipSlipTraversal struct{}

func (r *ZipSlipTraversal) ID() string                    { return "BATOU-TRV-010" }
func (r *ZipSlipTraversal) Name() string                  { return "ZipSlipTraversal" }
func (r *ZipSlipTraversal) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *ZipSlipTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJava, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ZipSlipTraversal) Description() string {
	return "Detects zip/tar archive extraction where entry names are used to construct file paths without validating that the result stays within the target directory (zip slip attack)."
}

func (r *ZipSlipTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if isComment(trimmed) {
			continue
		}

		var matched string
		var confidence string

		switch ctx.Language {
		case rules.LangGo:
			if loc := goZipSlipJoinCreate.FindString(line); loc != "" {
				if !hasZipSlipValidation(lines, i) {
					matched = loc
					confidence = "high"
				}
			}
		case rules.LangJava:
			if loc := javaZipSlipNewFile.FindString(line); loc != "" {
				if !hasZipSlipValidation(lines, i) {
					matched = loc
					confidence = "high"
				}
			}
			if matched == "" {
				if loc := javaZipSlipPath.FindString(line); loc != "" {
					if !hasZipSlipValidation(lines, i) {
						matched = loc
						confidence = "high"
					}
				}
			}
		case rules.LangPython:
			if pyTarImport.MatchString(ctx.Content) {
				if loc := pyTarExtract.FindString(line); loc != "" {
					// Safe if members= or filter= is used
					if !strings.Contains(line, "members=") && !strings.Contains(line, "members =") &&
						!strings.Contains(line, "filter=") && !strings.Contains(line, "filter =") {
						if !hasZipSlipValidation(lines, i) {
							matched = strings.TrimSpace(line)
							confidence = "high"
						}
					}
				}
			}
			if matched == "" {
				if loc := pyZipSlipManual.FindString(line); loc != "" {
					if !hasZipSlipValidation(lines, i) {
						matched = loc
						confidence = "medium"
					}
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if loc := jsZipSlipWrite.FindString(line); loc != "" {
				if !hasZipSlipValidation(lines, i) {
					matched = loc
					confidence = "high"
				}
			}
			if matched == "" {
				if loc := jsZipSlipEntry.FindString(line); loc != "" {
					if !hasZipSlipValidation(lines, i) {
						matched = loc
						confidence = "high"
					}
				}
			}
		}

		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				Title:         "Zip Slip: archive entry path used without validation",
				Description:   "Archive entry names (from zip/tar) are used to construct file paths without checking for path traversal sequences (../). An attacker can craft a malicious archive that writes files outside the intended extraction directory.",
				LineNumber:    lineNum,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate that the resolved path starts with the intended destination directory. In Go: use filepath.Clean + strings.HasPrefix. In Java: use getCanonicalPath() and verify prefix. In Python: use os.path.realpath and check prefix. In JS: use path.resolve and verify it starts with the target dir.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Confidence:    confidence,
				Tags:          []string{"traversal", "zip-slip", "archive", "path-traversal"},
			})
		}
	}

	return findings
}

// hasZipSlipValidation checks for common zip slip mitigation patterns in the function scope.
func hasZipSlipValidation(lines []string, idx int) bool {
	start, end := functionScope(lines, idx)

	for _, l := range lines[start:end] {
		// Go: strings.HasPrefix after filepath.Clean
		if strings.Contains(l, "strings.HasPrefix") || strings.Contains(l, "strings.Contains") {
			return true
		}
		// Go/general: checking for ".."
		if strings.Contains(l, `".."`) || strings.Contains(l, `'..`) {
			if strings.Contains(l, "if") || strings.Contains(l, "err") || strings.Contains(l, "return") {
				return true
			}
		}
		// Java: getCanonicalPath
		if strings.Contains(l, "getCanonicalPath") || strings.Contains(l, "getCanonicalFile") {
			return true
		}
		// Java: normalize + startsWith
		if strings.Contains(l, ".normalize()") && strings.Contains(l, ".startsWith(") {
			return true
		}
		// Python: os.path.realpath / os.path.commonpath / os.path.commonprefix
		if strings.Contains(l, "os.path.realpath") || strings.Contains(l, "os.path.commonpath") ||
			strings.Contains(l, "os.path.commonprefix") {
			return true
		}
		// Python: .startswith check
		if strings.Contains(l, ".startswith(") {
			return true
		}
		// JS: path.resolve + startsWith
		if strings.Contains(l, "path.resolve") && strings.Contains(l, ".startsWith(") {
			return true
		}
		// filepath.Clean + prefix check
		if strings.Contains(l, "filepath.Clean") || strings.Contains(l, "filepath.Abs") {
			return true
		}
	}

	return false
}

// --- Helpers ---

func isComment(line string) bool {
	return strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "#") ||
		strings.HasPrefix(line, "*") ||
		strings.HasPrefix(line, "/*") ||
		strings.HasPrefix(line, "<!--")
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
