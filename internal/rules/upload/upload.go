package upload

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns
// ---------------------------------------------------------------------------

// BATOU-UPLOAD-001: File upload without type validation
var (
	reUploadNoValidationPy    = regexp.MustCompile(`(?i)(?:request\.files|upload|uploaded_file|file_upload)\s*[\[.]\s*["']?\w+["']?\s*\]?\s*\.save\s*\(`)
	reUploadNoValidationPHP   = regexp.MustCompile(`(?i)move_uploaded_file\s*\(\s*\$_FILES`)
	reUploadNoValidationJS    = regexp.MustCompile(`(?i)(?:multer|upload|formidable|busboy)\s*[\({]`)
	reUploadNoValidationJava  = regexp.MustCompile(`(?i)(?:MultipartFile|Part)\s+\w+.*\.transferTo\s*\(`)
	reUploadNoValidationRuby  = regexp.MustCompile(`(?i)(?:params\s*\[\s*:?\w*file\w*\s*\]|uploaded_io)\.(?:read|path|original_filename)`)
	reUploadNoValidationGo    = regexp.MustCompile(`(?i)r\.FormFile\s*\(\s*["']\w+["']\s*\)`)
	reUploadTypeCheck         = regexp.MustCompile(`(?i)(?:content.?type|mime.?type|file.?type|extension|\.endswith|\.ends_with|getContentType|content_type|mimetype|ALLOWED_EXTENSIONS|allowed_types|accept|file_filter|fileFilter)`)
)

// BATOU-UPLOAD-002: File upload path traversal
var (
	reUploadPathTraversalConcat   = regexp.MustCompile(`(?i)(?:os\.path\.join|Path\.Combine|filepath\.Join|path\.join|File\.join)\s*\([^,)]*,\s*(?:request\.|req\.|params|filename|original_filename|getOriginalFilename|originalname|\$_FILES)`)
	reUploadPathTraversalDirect   = regexp.MustCompile(`(?i)(?:upload_dir|upload_path|save_path|dest|destination)\s*[=+]\s*[^;]*(?:filename|original_filename|originalname|\$_FILES\s*\[\s*["']\w+["']\s*\]\s*\[\s*["']name["']\])`)
	reUploadPathTraversalUnsafe   = regexp.MustCompile(`(?i)(?:open|fopen|File\.new|os\.Create|ioutil\.WriteFile)\s*\([^)]*(?:filename|original_filename|originalname|getOriginalFilename)`)
	reUploadPathSanitize          = regexp.MustCompile(`(?i)(?:secure_filename|basename|File\.basename|filepath\.Base|path\.basename|Path\.GetFileName|sanitize|strip_path)`)
)

// BATOU-UPLOAD-003: Upload to publicly accessible directory
var (
	reUploadPublicDir = regexp.MustCompile(`(?i)(?:upload_dir|upload_path|save_path|dest|destination|upload_folder)\s*[=:]\s*["'](?:[^"']*(?:public|static|www|wwwroot|htdocs|webroot|assets|media|uploads)/?)["']`)
	reUploadPublicJoin = regexp.MustCompile(`(?i)(?:os\.path\.join|Path\.Combine|filepath\.Join|path\.join)\s*\([^)]*(?:public|static|www|wwwroot|htdocs|webroot|assets)`)
)

// BATOU-UPLOAD-004: File upload without size limit
var (
	reUploadNoSizePy     = regexp.MustCompile(`(?i)(?:MAX_CONTENT_LENGTH|max_content_length|MAX_UPLOAD_SIZE)\s*[=:]\s*None`)
	reUploadNoSizePHP    = regexp.MustCompile(`(?i)(?:upload_max_filesize|post_max_size)\s*=\s*(?:0|-1|unlimited)`)
	reUploadNoSizeJS     = regexp.MustCompile(`(?i)multer\s*\(\s*\{[^}]*\}\s*\)`)
	reUploadHasLimits    = regexp.MustCompile(`(?i)limits\s*:`)
	reUploadNoSizeJSNone = regexp.MustCompile(`(?i)(?:limits\s*:\s*\{[^}]*fileSize\s*:\s*(?:Infinity|null|undefined|0))`)
	reUploadNoSizeJava   = regexp.MustCompile(`(?i)(?:setMaxFileSize|setMaxRequestSize)\s*\(\s*-1\s*\)`)
)

// BATOU-UPLOAD-005: Upload without magic byte/content verification
var (
	reUploadExtensionOnly = regexp.MustCompile(`(?i)(?:\.endswith|\.ends_with|\.toLowerCase\(\)\s*===?\s*["']\.\w+["']|\.extension|getOriginalFilename\(\)\.(?:split|substring|endsWith)|\.split\s*\(\s*["']\.\s*["']\s*\)\s*\.pop)`)
	reUploadMagicCheck    = regexp.MustCompile(`(?i)(?:magic|python-magic|file.?type|imghdr|filetype|mime\.magic|FileTypeDetector|content.?inspection|magic_bytes|file_header|read\s*\(\s*\d+\s*\)|fileTypeFromBuffer|fromBuffer)`)
)

// BATOU-UPLOAD-006: Executable file extension allowed
var (
	reUploadExecutableExt = regexp.MustCompile(`(?i)(?:allowed|accept|permit|valid|whitelist|allowlist)(?:_)?(?:ext|extension|type|format)s?\s*[=:]\s*[\[({][^)\]}]*["']\.?(?:php|phtml|php[345]|pht|jsp|jspx|asp|aspx|exe|sh|bat|cmd|cgi|pl|py|rb|war|jar)["']`)
	reUploadNoExtBlock    = regexp.MustCompile(`(?i)(?:\.(?:php|jsp|asp|aspx|exe|sh|bat|cmd|cgi|war|jar))\s*["']\s*(?:=>|:)\s*(?:true|["'](?:allow|accept))`)
)

// BATOU-UPLOAD-007: SVG upload without sanitization
var (
	reUploadSVGAllow    = regexp.MustCompile(`(?i)(?:allowed|accept|permit|valid|whitelist|allowlist)(?:_)?(?:ext|extension|type|format|mime)s?\s*[=:]\s*[\[({][^)\]}]*["'](?:\.svg|image/svg|svg)["']`)
	reUploadSVGMime     = regexp.MustCompile(`(?i)(?:content.?type|mime.?type)\s*(?:===?|==|\.includes|\.contains)\s*["']image/svg`)
	reUploadSVGSanitize = regexp.MustCompile(`(?i)(?:sanitize.?svg|svg.?sanitize|DOMPurify|clean.?svg|svg.?clean|bleach|defused)`)
)

// BATOU-UPLOAD-008: Client-side only upload validation
var (
	reClientSideValidation = regexp.MustCompile(`(?i)(?:accept\s*=\s*["'][^"']+["']|\.files\s*\[\s*0\s*\]\s*\.(?:type|name|size)|input\.files|event\.target\.files|FileReader|(?:onChange|onchange)\s*=)`)
	reClientSideTypeCheck  = regexp.MustCompile(`(?i)(?:file\.type\s*(?:===?|!==?|==)\s*["']|file\.name\.(?:endsWith|match|split)|\.accept\s*=)`)
	reClientSideSizeCheck  = regexp.MustCompile(`(?i)(?:file\.size\s*(?:>|<|>=|<=)\s*\d+)`)
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

func hasNearbyPattern(lines []string, idx, before, after int, re *regexp.Regexp) bool {
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := idx + after + 1
	if end > len(lines) {
		end = len(lines)
	}
	for _, l := range lines[start:end] {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-001: File upload without type validation
// ---------------------------------------------------------------------------

type UploadNoTypeValidation struct{}

func (r *UploadNoTypeValidation) ID() string                     { return "BATOU-UPLOAD-001" }
func (r *UploadNoTypeValidation) Name() string                   { return "UploadNoTypeValidation" }
func (r *UploadNoTypeValidation) DefaultSeverity() rules.Severity { return rules.High }
func (r *UploadNoTypeValidation) Description() string {
	return "Detects file upload handlers that save or process uploaded files without validating the file type, potentially allowing upload of malicious files."
}
func (r *UploadNoTypeValidation) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *UploadNoTypeValidation) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var uploadPatterns []*regexp.Regexp
	switch ctx.Language {
	case rules.LangPython:
		uploadPatterns = []*regexp.Regexp{reUploadNoValidationPy}
	case rules.LangPHP:
		uploadPatterns = []*regexp.Regexp{reUploadNoValidationPHP}
	case rules.LangJavaScript, rules.LangTypeScript:
		uploadPatterns = []*regexp.Regexp{reUploadNoValidationJS}
	case rules.LangJava:
		uploadPatterns = []*regexp.Regexp{reUploadNoValidationJava}
	case rules.LangRuby:
		uploadPatterns = []*regexp.Regexp{reUploadNoValidationRuby}
	case rules.LangGo:
		uploadPatterns = []*regexp.Regexp{reUploadNoValidationGo}
	default:
		return findings
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range uploadPatterns {
			if m := re.FindString(line); m != "" {
				// Check if type validation exists nearby
				if hasNearbyPattern(lines, i, 10, 10, reUploadTypeCheck) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File upload without type validation",
					Description:   "File is saved/processed without validating its type (extension, MIME type, or content). An attacker could upload a web shell, malware, or other malicious files.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Validate file type using an allowlist of permitted extensions AND verify content type. Check magic bytes for additional assurance. Use secure_filename() to sanitize the filename.",
					CWEID:         "CWE-434",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"upload", "file-upload", "unrestricted-upload"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-002: File upload path traversal
// ---------------------------------------------------------------------------

type UploadPathTraversal struct{}

func (r *UploadPathTraversal) ID() string                     { return "BATOU-UPLOAD-002" }
func (r *UploadPathTraversal) Name() string                   { return "UploadPathTraversal" }
func (r *UploadPathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *UploadPathTraversal) Description() string {
	return "Detects file upload operations that use the original filename from the user without path sanitization, enabling path traversal attacks."
}
func (r *UploadPathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *UploadPathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reUploadPathTraversalConcat, reUploadPathTraversalDirect, reUploadPathTraversalUnsafe} {
			if m := re.FindString(line); m != "" {
				// Check for path sanitization nearby
				if hasNearbyPattern(lines, i, 5, 5, reUploadPathSanitize) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File upload path traversal",
					Description:   "Uploaded file is saved using the original filename without sanitization. An attacker can use path traversal (../../../etc/crontab) to write files outside the upload directory.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Use secure_filename() (Python), path.basename() (Node.js), filepath.Base() (Go), or Path.GetFileName() (C#) to strip path components. Better yet, generate a random filename and store the original name in a database.",
					CWEID:         "CWE-22",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"upload", "path-traversal", "file-write"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-003: Upload to publicly accessible directory
// ---------------------------------------------------------------------------

type UploadPublicDir struct{}

func (r *UploadPublicDir) ID() string                     { return "BATOU-UPLOAD-003" }
func (r *UploadPublicDir) Name() string                   { return "UploadPublicDir" }
func (r *UploadPublicDir) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UploadPublicDir) Description() string {
	return "Detects file upload configurations that save files to publicly accessible directories (public/, static/, www/), which may allow direct execution of uploaded files."
}
func (r *UploadPublicDir) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *UploadPublicDir) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reUploadPublicDir, reUploadPublicJoin} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Upload to publicly accessible directory",
					Description:   "Uploaded files are saved to a publicly accessible directory. If the web server is configured to execute scripts in this directory, an uploaded web shell can be directly accessed and executed.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Store uploads outside the web root in a non-executable directory. Serve files through an application route that sets Content-Disposition: attachment and validates access permissions.",
					CWEID:         "CWE-434",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"upload", "public-directory", "web-shell"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-004: File upload without size limit
// ---------------------------------------------------------------------------

type UploadNoSizeLimit struct{}

func (r *UploadNoSizeLimit) ID() string                     { return "BATOU-UPLOAD-004" }
func (r *UploadNoSizeLimit) Name() string                   { return "UploadNoSizeLimit" }
func (r *UploadNoSizeLimit) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UploadNoSizeLimit) Description() string {
	return "Detects file upload configurations that do not enforce a size limit, enabling denial-of-service via large file uploads."
}
func (r *UploadNoSizeLimit) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP}
}

func (r *UploadNoSizeLimit) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	var patterns []*regexp.Regexp
	switch ctx.Language {
	case rules.LangPython:
		patterns = []*regexp.Regexp{reUploadNoSizePy}
	case rules.LangPHP:
		patterns = []*regexp.Regexp{reUploadNoSizePHP}
	case rules.LangJavaScript, rules.LangTypeScript:
		patterns = []*regexp.Regexp{reUploadNoSizeJS, reUploadNoSizeJSNone}
	case rules.LangJava:
		patterns = []*regexp.Regexp{reUploadNoSizeJava}
	default:
		return findings
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range patterns {
			if m := re.FindString(line); m != "" {
				// For multer(...{...}), skip if the config object contains "limits"
				if re == reUploadNoSizeJS && reUploadHasLimits.MatchString(m) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "File upload without size limit",
					Description:   "File upload handler does not enforce a maximum file size. An attacker can upload extremely large files to exhaust disk space or memory, causing denial of service.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Set a maximum file size limit appropriate for your use case. Use MAX_CONTENT_LENGTH (Flask), limits.fileSize (multer), upload_max_filesize (PHP), or @MultipartConfig maxFileSize (Java).",
					CWEID:         "CWE-400",
					OWASPCategory: "A05:2021-Security Misconfiguration",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"upload", "size-limit", "dos"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-005: Upload without magic byte/content verification
// ---------------------------------------------------------------------------

type UploadNoMagicBytes struct{}

func (r *UploadNoMagicBytes) ID() string                     { return "BATOU-UPLOAD-005" }
func (r *UploadNoMagicBytes) Name() string                   { return "UploadNoMagicBytes" }
func (r *UploadNoMagicBytes) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UploadNoMagicBytes) Description() string {
	return "Detects file upload validation that only checks the file extension without verifying actual file content via magic bytes, allowing extension spoofing."
}
func (r *UploadNoMagicBytes) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *UploadNoMagicBytes) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reUploadExtensionOnly.FindString(line); m != "" {
			// Check if magic byte verification exists nearby
			if hasNearbyPattern(lines, i, 15, 15, reUploadMagicCheck) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Upload validation by extension only (no content verification)",
				Description:   "File upload validation relies solely on the file extension, which is trivially spoofable. A PHP web shell can be uploaded as 'shell.php.jpg' or by manipulating the extension check.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "Verify file content using magic bytes (file headers) in addition to extension checks. Use python-magic, file-type (npm), or Apache Tika to detect true file types.",
				CWEID:         "CWE-434",
				OWASPCategory: "A04:2021-Insecure Design",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"upload", "extension-spoofing", "magic-bytes"},
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-006: Executable file extension allowed
// ---------------------------------------------------------------------------

type UploadExecutableExt struct{}

func (r *UploadExecutableExt) ID() string                     { return "BATOU-UPLOAD-006" }
func (r *UploadExecutableExt) Name() string                   { return "UploadExecutableExt" }
func (r *UploadExecutableExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *UploadExecutableExt) Description() string {
	return "Detects file upload configurations that explicitly allow executable file extensions (php, jsp, asp, exe, sh, etc.), enabling remote code execution."
}
func (r *UploadExecutableExt) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *UploadExecutableExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reUploadExecutableExt, reUploadNoExtBlock} {
			if m := re.FindString(line); m != "" {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Executable file extension allowed in upload",
					Description:   "The upload configuration allows executable file extensions (php, jsp, asp, exe, sh, etc.). An attacker can upload a web shell or executable that will be run by the web server.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Only allow safe, non-executable file extensions (jpg, png, pdf, docx, etc.). Block all server-side script extensions. Use a strict allowlist approach, not a denylist.",
					CWEID:         "CWE-434",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "high",
					Tags:          []string{"upload", "executable", "web-shell", "rce"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-007: SVG upload without sanitization
// ---------------------------------------------------------------------------

type UploadSVGNoSanitize struct{}

func (r *UploadSVGNoSanitize) ID() string                     { return "BATOU-UPLOAD-007" }
func (r *UploadSVGNoSanitize) Name() string                   { return "UploadSVGNoSanitize" }
func (r *UploadSVGNoSanitize) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UploadSVGNoSanitize) Description() string {
	return "Detects SVG file upload acceptance without sanitization. SVG files can contain embedded JavaScript (<script> tags, event handlers) that execute as XSS when rendered."
}
func (r *UploadSVGNoSanitize) Languages() []rules.Language {
	return []rules.Language{rules.LangPython, rules.LangJavaScript, rules.LangTypeScript, rules.LangJava, rules.LangPHP, rules.LangRuby, rules.LangGo}
}

func (r *UploadSVGNoSanitize) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		for _, re := range []*regexp.Regexp{reUploadSVGAllow, reUploadSVGMime} {
			if m := re.FindString(line); m != "" {
				// Check for SVG sanitization nearby
				if hasNearbyPattern(lines, i, 15, 15, reUploadSVGSanitize) {
					continue
				}
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "SVG upload without sanitization (XSS vector)",
					Description:   "SVG files are accepted for upload without sanitization. SVG is an XML format that can contain <script> tags, onload handlers, and other XSS vectors that execute when the SVG is rendered in a browser.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Sanitize SVG files using DOMPurify or a similar library to remove scripts and event handlers. Alternatively, convert SVGs to raster images (PNG) before serving, or serve with Content-Disposition: attachment and Content-Type: application/octet-stream.",
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"upload", "svg", "xss", "sanitization"},
				})
				break
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// BATOU-UPLOAD-008: Client-side only upload validation
// ---------------------------------------------------------------------------

type UploadClientSideOnly struct{}

func (r *UploadClientSideOnly) ID() string                     { return "BATOU-UPLOAD-008" }
func (r *UploadClientSideOnly) Name() string                   { return "UploadClientSideOnly" }
func (r *UploadClientSideOnly) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *UploadClientSideOnly) Description() string {
	return "Detects file upload validation performed only on the client side (JavaScript), which can be trivially bypassed by modifying the request directly."
}
func (r *UploadClientSideOnly) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *UploadClientSideOnly) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")

	// Detect client-side file validation patterns
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reClientSideTypeCheck.FindString(line); m != "" {
			// Also check for size validation on the same or nearby lines
			hasSizeCheck := reClientSideSizeCheck.MatchString(line) ||
				hasNearbyPattern(lines, i, 3, 3, reClientSideSizeCheck)
			if hasSizeCheck || reClientSideValidation.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Client-side only upload validation",
					Description:   "File upload validation is performed in client-side JavaScript (checking file.type, file.name, file.size). This can be trivially bypassed using browser dev tools, curl, or a proxy. All validation must also be enforced server-side.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(m, 120),
					Suggestion:    "Always enforce file type, size, and content validation on the server side. Client-side validation is for UX only and must never be the sole validation layer.",
					CWEID:         "CWE-602",
					OWASPCategory: "A04:2021-Insecure Design",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"upload", "client-side-validation", "bypass"},
				})
			}
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&UploadNoTypeValidation{})
	rules.Register(&UploadPathTraversal{})
	rules.Register(&UploadPublicDir{})
	rules.Register(&UploadNoSizeLimit{})
	rules.Register(&UploadNoMagicBytes{})
	rules.Register(&UploadExecutableExt{})
	rules.Register(&UploadSVGNoSanitize{})
	rules.Register(&UploadClientSideOnly{})
}
