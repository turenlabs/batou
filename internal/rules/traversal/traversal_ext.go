package traversal

import (
	"regexp"
	"strings"

	"github.com/turenio/gtss/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended traversal detection
// ---------------------------------------------------------------------------

var (
	// GTSS-TRV-011: Zip slip vulnerability (archive extraction)
	reExtZipSlipGo     = regexp.MustCompile(`(?:zip\.File|tar\.Header|zip\.Reader|tar\.Reader)`)
	reExtZipSlipCreate = regexp.MustCompile(`(?:os\.Create|os\.OpenFile|os\.MkdirAll|ioutil\.WriteFile)\s*\([^)]*(?:\.Name\b|header\.Name|entry|f\.Name|file\.Name)`)
	reExtZipSlipJava   = regexp.MustCompile(`(?:ZipEntry|TarArchiveEntry|JarEntry)\s*.*(?:getName|getPath)\s*\(`)
	reExtZipSlipPy     = regexp.MustCompile(`\.(?:extractall|extract)\s*\([^)]*\)`)
	reExtZipSlipJS     = regexp.MustCompile(`(?:entry\.(?:fileName|path|name)|zipEntry)\s*`)

	// GTSS-TRV-012: Path traversal via URL-encoded sequences
	reExtURLEncodedTraversal = regexp.MustCompile(`(?:%2e%2e|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|\.\.%5c|%252e%252e|%c0%ae|%c1%9c)`)
	reExtDecodeURI           = regexp.MustCompile(`(?i)(?:decodeURI|urldecode|url_decode|URLDecoder\.decode|QueryUnescape|unquote)\s*\(`)

	// GTSS-TRV-013: Symlink following in file operations
	reExtSymlinkFollow   = regexp.MustCompile(`(?:os\.Readlink|readlink|File\.readlink|os\.readlink|fs\.readlink|Path\.readlink|lstat)\s*\(`)
	reExtSymlinkValidate = regexp.MustCompile(`(?i)(?:filepath\.EvalSymlinks|os\.path\.realpath|fs\.realpathSync|File\.realpath|readlink.*realpath|symlink.*check|lstat.*isSymbolicLink)`)

	// GTSS-TRV-014: Path traversal in template include/require
	reExtTemplateInclude = regexp.MustCompile(`(?i)(?:include|require|require_once|include_once|load|render)\s*[\(]?\s*(?:\$(?:_GET|_POST|_REQUEST)|req\.(?:query|params|body)|request\.(?:GET|POST|args|form)|params\[)`)

	// GTSS-TRV-015: Directory listing enabled
	reExtDirListing     = regexp.MustCompile(`(?i)(?:express\.static|serveStatic|directory_listing|autoindex\s+on|Options\s+\+?Indexes|DirectoryIndex|enable_dir_listing|browse\s*=\s*true|list_?directory|FancyIndexing)`)
	reExtDirListingPy   = regexp.MustCompile(`(?i)(?:send_from_directory|SimpleHTTPServer|http\.server|directory_listing\s*=\s*True)`)

	// GTSS-TRV-016: Absolute path traversal (user controls full path)
	reExtAbsPathTraversal = regexp.MustCompile(`(?i)(?:os\.(?:Open|ReadFile|Create|Remove)|ioutil\.ReadFile|fs\.(?:readFile|writeFile|readFileSync|writeFileSync)|open|fopen|file_get_contents|File\.(?:read|open|write))\s*\(\s*(?:req\.(?:query|params|body)\s*[\[.]|request\.(?:GET|POST|args|form)\s*[\[.]|params\[|\$_(?:GET|POST|REQUEST)\[)`)

	// GTSS-TRV-017: Path traversal via null byte injection
	reExtNullByteInPath  = regexp.MustCompile(`(?:%00|\\x00|\\0|\\u0000)`)
	reExtFileOpWithInput = regexp.MustCompile(`(?i)(?:open|readFile|readFileSync|fopen|file_get_contents|ReadFile|Open|sendFile|download)\s*\(`)

	// GTSS-TRV-018: Unsafe file serve (serving user-specified path)
	reExtUnsafeServe = regexp.MustCompile(`(?i)(?:res\.sendFile|res\.download|send_file|send_from_directory|serve_file|FileResponse|StreamingResponse)\s*\(\s*(?:req\.|request\.|params|path|file|input|user)`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&ZipSlipExt{})
	rules.Register(&URLEncodedTraversal{})
	rules.Register(&SymlinkFollowingExt{})
	rules.Register(&TemplateIncludeTraversal{})
	rules.Register(&DirectoryListingEnabled{})
	rules.Register(&AbsolutePathTraversal{})
	rules.Register(&NullByteTraversal{})
	rules.Register(&UnsafeFileServe{})
}

// ========================================================================
// GTSS-TRV-011: Zip Slip Vulnerability
// ========================================================================

type ZipSlipExt struct{}

func (r *ZipSlipExt) ID() string                     { return "GTSS-TRV-011" }
func (r *ZipSlipExt) Name() string                   { return "ZipSlipExt" }
func (r *ZipSlipExt) DefaultSeverity() rules.Severity { return rules.High }
func (r *ZipSlipExt) Description() string {
	return "Detects archive extraction patterns without path validation that may allow zip-slip attacks."
}
func (r *ZipSlipExt) Languages() []rules.Language {
	return []rules.Language{rules.LangGo, rules.LangJava, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript}
}

func (r *ZipSlipExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var matched string
		switch ctx.Language {
		case rules.LangGo:
			if m := reExtZipSlipCreate.FindString(line); m != "" {
				if !hasTraversalGuard(lines, i) {
					matched = m
				}
			}
		case rules.LangJava:
			if m := reExtZipSlipJava.FindString(line); m != "" {
				if !hasZipSlipValidation(lines, i) {
					matched = m
				}
			}
		case rules.LangPython:
			if m := reExtZipSlipPy.FindString(line); m != "" {
				if !strings.Contains(line, "members=") && !strings.Contains(line, "filter=") {
					if !hasTraversalGuard(lines, i) {
						matched = m
					}
				}
			}
		case rules.LangJavaScript, rules.LangTypeScript:
			if m := reExtZipSlipJS.FindString(line); m != "" {
				if strings.Contains(line, "write") || strings.Contains(line, "create") || strings.Contains(line, "path.join") {
					if !hasTraversalGuard(lines, i) {
						matched = m
					}
				}
			}
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Zip slip: archive entry path used without validation",
				Description:   "Archive entry names are used to construct file paths without checking for path traversal sequences (../). A malicious archive can write files outside the extraction directory.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(matched, 120),
				Suggestion:    "Validate that the resolved extraction path starts with the intended destination directory. Use filepath.Clean + strings.HasPrefix (Go), getCanonicalPath (Java), os.path.realpath (Python).",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"traversal", "zip-slip", "archive"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-012: Path Traversal via URL-Encoded Sequences
// ========================================================================

type URLEncodedTraversal struct{}

func (r *URLEncodedTraversal) ID() string                     { return "GTSS-TRV-012" }
func (r *URLEncodedTraversal) Name() string                   { return "URLEncodedTraversal" }
func (r *URLEncodedTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *URLEncodedTraversal) Description() string {
	return "Detects URL-encoded path traversal sequences (%2e%2e) or URL decoding followed by file operations."
}
func (r *URLEncodedTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *URLEncodedTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtURLEncodedTraversal.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "URL-encoded path traversal sequence detected",
				Description:   "URL-encoded path traversal sequences (%2e%2e, %252e, etc.) were found. These can bypass path validation that only checks for literal '../' strings.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(strings.TrimSpace(line), 120),
				Suggestion:    "Decode URLs before path validation. Apply path canonicalization (realpath/filepath.Clean) after decoding and verify the result is within the expected directory.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"traversal", "url-encoding", "bypass"},
			})
		}
		// Also detect URL decoding followed by file I/O
		if m := reExtDecodeURI.FindString(line); m != "" {
			// Check if file operations follow nearby
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			for _, subsequent := range lines[i+1 : end] {
				subLower := strings.ToLower(subsequent)
				if strings.Contains(subLower, "open") || strings.Contains(subLower, "readfile") ||
					strings.Contains(subLower, "sendfile") || strings.Contains(subLower, "include") {
					if !hasTraversalGuard(lines, i) {
						findings = append(findings, rules.Finding{
							RuleID:        r.ID(),
							Severity:      r.DefaultSeverity(),
							SeverityLabel: r.DefaultSeverity().String(),
							Title:         "URL decoding before file operation (double-encoding bypass risk)",
							Description:   "URL decoding is performed before file operations. If path validation happens before decoding, double-encoded traversal sequences can bypass the check.",
							FilePath:      ctx.FilePath,
							LineNumber:    i + 1,
							MatchedText:   truncate(m, 120),
							Suggestion:    "Validate paths after all decoding is complete. Apply canonicalization (realpath/filepath.Clean) as the final step before any file operation.",
							CWEID:         "CWE-22",
							OWASPCategory: "A01:2021-Broken Access Control",
							Language:      ctx.Language,
							Confidence:    "medium",
							Tags:          []string{"traversal", "url-decoding", "double-encoding"},
						})
					}
					break
				}
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-013: Symlink Following in File Operations
// ========================================================================

type SymlinkFollowingExt struct{}

func (r *SymlinkFollowingExt) ID() string                     { return "GTSS-TRV-013" }
func (r *SymlinkFollowingExt) Name() string                   { return "SymlinkFollowingExt" }
func (r *SymlinkFollowingExt) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *SymlinkFollowingExt) Description() string {
	return "Detects symlink resolution without subsequent path validation, which may allow symlink-based file access attacks."
}
func (r *SymlinkFollowingExt) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *SymlinkFollowingExt) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtSymlinkFollow.FindString(line); m != "" {
			// Check if validation follows
			end := i + 10
			if end > len(lines) {
				end = len(lines)
			}
			block := strings.Join(lines[i:end], "\n")
			if reExtSymlinkValidate.MatchString(block) {
				continue
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Symlink resolution without path validation",
				Description:   "A symlink is resolved but the resulting path is not validated against an expected base directory. An attacker who controls the symlink can redirect file operations to arbitrary paths.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   truncate(m, 120),
				Suggestion:    "After resolving symlinks, use realpath/filepath.EvalSymlinks and verify the result starts with the expected directory prefix.",
				CWEID:         "CWE-59",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"traversal", "symlink", "toctou"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-014: Path Traversal in Template Include/Require
// ========================================================================

type TemplateIncludeTraversal struct{}

func (r *TemplateIncludeTraversal) ID() string                     { return "GTSS-TRV-014" }
func (r *TemplateIncludeTraversal) Name() string                   { return "TemplateIncludeTraversal" }
func (r *TemplateIncludeTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *TemplateIncludeTraversal) Description() string {
	return "Detects file include/require operations with user-controlled paths, enabling Local File Inclusion (LFI)."
}
func (r *TemplateIncludeTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP, rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangRuby}
}

func (r *TemplateIncludeTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtTemplateInclude.FindString(line); m != "" {
			if hasTraversalGuard(lines, i) {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "File include/require with user-controlled path (LFI risk)",
				Description:   "An include/require/render statement uses a path from user input. An attacker can read arbitrary files or execute code by traversing to system files (/etc/passwd, config files).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use an allowlist of permitted template/file names. Never pass user input directly to include/require. Use basename() to strip directory components.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"traversal", "lfi", "template-include"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-015: Directory Listing Enabled
// ========================================================================

type DirectoryListingEnabled struct{}

func (r *DirectoryListingEnabled) ID() string                     { return "GTSS-TRV-015" }
func (r *DirectoryListingEnabled) Name() string                   { return "DirectoryListingEnabled" }
func (r *DirectoryListingEnabled) DefaultSeverity() rules.Severity { return rules.Medium }
func (r *DirectoryListingEnabled) Description() string {
	return "Detects web server configuration that enables directory listing, exposing file structure to attackers."
}
func (r *DirectoryListingEnabled) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *DirectoryListingEnabled) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		var matched string
		if m := reExtDirListing.FindString(line); m != "" {
			matched = m
		} else if m := reExtDirListingPy.FindString(line); m != "" {
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
				Title:         "Directory listing enabled",
				Description:   "Directory listing is enabled, which allows attackers to browse the file structure of the web server and discover sensitive files, backup files, or configuration files.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Disable directory listing. In Apache: Options -Indexes. In Nginx: autoindex off. In Express: do not use serveIndex. Serve specific files instead.",
				CWEID:         "CWE-548",
				OWASPCategory: "A05:2021-Security Misconfiguration",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"traversal", "directory-listing", "information-disclosure"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-016: Absolute Path Traversal
// ========================================================================

type AbsolutePathTraversal struct{}

func (r *AbsolutePathTraversal) ID() string                     { return "GTSS-TRV-016" }
func (r *AbsolutePathTraversal) Name() string                   { return "AbsolutePathTraversal" }
func (r *AbsolutePathTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *AbsolutePathTraversal) Description() string {
	return "Detects file operations where the full path comes from user input, enabling absolute path traversal."
}
func (r *AbsolutePathTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *AbsolutePathTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtAbsPathTraversal.FindString(line); m != "" {
			if hasTraversalGuard(lines, i) {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "File operation with user-controlled absolute path",
				Description:   "A file operation uses a path directly from user input. The user can specify any absolute path (e.g., /etc/passwd) to read or write arbitrary files on the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Never use raw user input as a file path. Join user input with a base directory and validate the canonical result stays within that directory.",
				CWEID:         "CWE-36",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"traversal", "absolute-path", "file-access"},
			})
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-017: Path Traversal via Null Byte Injection
// ========================================================================

type NullByteTraversal struct{}

func (r *NullByteTraversal) ID() string                     { return "GTSS-TRV-017" }
func (r *NullByteTraversal) Name() string                   { return "NullByteTraversal" }
func (r *NullByteTraversal) DefaultSeverity() rules.Severity { return rules.High }
func (r *NullByteTraversal) Description() string {
	return "Detects null byte sequences in file paths that can truncate file extensions and bypass validation."
}
func (r *NullByteTraversal) Languages() []rules.Language {
	return []rules.Language{rules.LangAny}
}

func (r *NullByteTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtNullByteInPath.FindString(line); m != "" {
			// Only flag if near file operations
			if reExtFileOpWithInput.MatchString(line) || hasUserInputIndicator(lines, i) {
				findings = append(findings, rules.Finding{
					RuleID:        r.ID(),
					Severity:      r.DefaultSeverity(),
					SeverityLabel: r.DefaultSeverity().String(),
					Title:         "Null byte in file path (extension bypass risk)",
					Description:   "A null byte sequence was found in a context involving file operations. Null bytes can truncate file paths in some runtimes (PHP < 5.3.4, older Node.js), bypassing file extension checks.",
					FilePath:      ctx.FilePath,
					LineNumber:    i + 1,
					MatchedText:   truncate(strings.TrimSpace(line), 120),
					Suggestion:    "Strip null bytes from all user-supplied file paths before use. Reject paths containing null bytes entirely.",
					CWEID:         "CWE-158",
					OWASPCategory: "A01:2021-Broken Access Control",
					Language:      ctx.Language,
					Confidence:    "medium",
					Tags:          []string{"traversal", "null-byte", "extension-bypass"},
				})
			}
		}
	}
	return findings
}

// ========================================================================
// GTSS-TRV-018: Unsafe File Serve
// ========================================================================

type UnsafeFileServe struct{}

func (r *UnsafeFileServe) ID() string                     { return "GTSS-TRV-018" }
func (r *UnsafeFileServe) Name() string                   { return "UnsafeFileServe" }
func (r *UnsafeFileServe) DefaultSeverity() rules.Severity { return rules.High }
func (r *UnsafeFileServe) Description() string {
	return "Detects file serving functions (sendFile, download, send_file) with user-controlled paths."
}
func (r *UnsafeFileServe) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript, rules.LangPython, rules.LangRuby}
}

func (r *UnsafeFileServe) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isComment(trimmed) {
			continue
		}
		if m := reExtUnsafeServe.FindString(line); m != "" {
			if hasTraversalGuard(lines, i) {
				continue
			}
			matched := m
			if len(matched) > 120 {
				matched = matched[:120] + "..."
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "File serving with user-controlled path",
				Description:   "A file serving function uses a path derived from user input without visible path validation. An attacker can use path traversal to download any file from the server.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Resolve the path with realpath/path.resolve and verify it starts with the intended base directory. Use the root option in Express sendFile. Never serve user-specified absolute paths.",
				CWEID:         "CWE-22",
				OWASPCategory: "A01:2021-Broken Access Control",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"traversal", "file-serve", "path-traversal"},
			})
		}
	}
	return findings
}
