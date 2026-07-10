package cast

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// cast_libc_hardening.go gathers the framework-anchored libc misuse AST rules
// commonly covered by mainstream C security rulesets. Each keys on a
// UNIQUE reserved libc symbol, so there is no bare-name collision with
// application code, and each fires only on the structurally dangerous shape so
// the safe replacement (strtok_r, mkstemp, snprintf with a width, etc.) stays
// clean. Implemented independently from the CWE definitions and the C standard
// library specification.
//
//   BATOU-CAST-013  strtok()             obsolete non-reentrant tokenizer  CWE-477
//   BATOU-CAST-014  mktemp/tmpnam/tempnam predictable temp-file name      CWE-377
//   BATOU-CAST-015  scanf/fscanf/sscanf  unbounded %s/%[ into fixed buf   CWE-120
//   BATOU-CAST-016  memset() secret scrub the optimizer may elide         CWE-14
//   BATOU-CAST-018  /dev/random read in a loop without close             CWE-400

// checkLibcHardening dispatches the per-call libc hardening rules. Called for
// every call_expression node from walk().
func (c *cChecker) checkLibcHardening(n *ast.Node) {
	switch cCallName(n) {
	case "strtok":
		c.checkStrtok(n)
	case "mktemp", "tmpnam", "tempnam":
		c.checkInsecureTempFile(n)
	case "scanf", "fscanf", "sscanf":
		c.checkUnboundedScanf(n)
	case "memset":
		c.checkSecretScrub(n)
	}
}

// --- BATOU-CAST-013: strtok (CWE-477) ---------------------------------------

// checkStrtok flags use of strtok(), the non-reentrant obsolete tokenizer.
// strtok stores parse state in a hidden static buffer, so it is not thread-safe
// and breaks when two tokenizations interleave (e.g. a callee also using strtok
// mid-loop). strtok_r / strsep are the reentrant replacements and are NOT
// flagged because the switch above only matches the bare "strtok" identifier.
func (c *cChecker) checkStrtok(n *ast.Node) {
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-013",
		Severity:      rules.Low,
		SeverityLabel: rules.Low.String(),
		Title:         "Use of non-reentrant strtok()",
		Description: "strtok() keeps its parsing position in a hidden static buffer, making it non-reentrant and " +
			"unsafe across threads or when a nested call also tokenizes. Interleaved tokenization corrupts the " +
			"shared state and yields wrong results (CWE-477, obsolete function).",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use strtok_r(str, delim, &saveptr) (POSIX) or strsep(&str, delim), which keep the parse state in a caller-owned variable.",
		CWEID:         "CWE-477",
		OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"obsolete", "reentrancy", "libc", "ast"},
	})
}

// --- BATOU-CAST-014: mktemp/tmpnam/tempnam (CWE-377) ------------------------

// insecureTempFns maps the predictable temp-name generators to their safe
// replacement for the suggestion text.
var insecureTempFns = map[string]string{
	"mktemp":  "mkstemp",
	"tmpnam":  "mkstemp",
	"tempnam": "mkstemp",
}

// checkInsecureTempFile flags mktemp/tmpnam/tempnam, which only generate a
// file NAME (no atomic create-and-open). Between the name being generated and
// the program opening it, an attacker can create the path (often as a symlink),
// causing a time-of-check/time-of-use race that lets them control or read the
// target file (CWE-377). mkstemp/mkdtemp atomically create the file and are the
// safe replacement; they are NOT matched here.
func (c *cChecker) checkInsecureTempFile(n *ast.Node) {
	fn := cCallName(n)
	safe := insecureTempFns[fn]
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-014",
		Severity:      rules.Medium,
		SeverityLabel: rules.Medium.String(),
		Title:         "Insecure temporary file via " + fn + "()",
		Description: fn + "() returns a predictable temporary-file NAME without atomically creating the file. " +
			"An attacker who pre-creates that path (e.g. as a symlink) between the name generation and the open " +
			"wins a TOCTOU race and can redirect or read the file (CWE-377).",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use " + safe + "(template) (or mkdtemp for directories), which atomically creates the file with O_EXCL and returns an open fd, eliminating the race.",
		CWEID:         "CWE-377",
		OWASPCategory: "A01:2021-Broken Access Control",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"temp-file", "toctou", "libc", "ast"},
	})
}

// --- BATOU-CAST-015: unbounded scanf %s (CWE-120) ---------------------------

// scanfFmtArgIdx maps each scanf-family function to the index of its format
// string argument. scanf reads the format first; fscanf/sscanf read a
// stream/string first, then the format.
var scanfFmtArgIdx = map[string]int{
	"scanf":  0,
	"fscanf": 1,
	"sscanf": 1,
}

// checkUnboundedScanf flags scanf/fscanf/sscanf calls whose format string
// contains an UNBOUNDED %s or %[ conversion (no field-width). Such a conversion
// writes characters into the destination buffer until whitespace/EOF with no
// length limit, overflowing any fixed buffer the caller supplied — the classic
// scanf("%s", buf) overflow (CWE-120). A width-limited conversion ("%63s",
// "%63[^\n]") is bounded and is NOT flagged.
func (c *cChecker) checkUnboundedScanf(n *ast.Node) {
	fn := cCallName(n)
	fmtIdx, ok := scanfFmtArgIdx[fn]
	if !ok {
		return
	}
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if fmtIdx >= len(named) {
		return
	}
	fmtNode := named[fmtIdx]
	// The format must be a string literal we can inspect. A runtime format is a
	// different (format-string) class and not this check's concern.
	if fmtNode.Type() != "string_literal" {
		return
	}
	if !hasUnboundedStrConversion(fmtNode.Text()) {
		return
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-015",
		Severity:      rules.High,
		SeverityLabel: rules.High.String(),
		Title:         "Unbounded " + fn + "() string conversion (%s without field width)",
		Description: fn + "() uses an unbounded %s or %[ conversion. The conversion writes input into the " +
			"destination buffer with no length limit, so any input longer than that buffer overflows it " +
			"(CWE-120). This is exploitable whenever the buffer is a fixed-size stack array.",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Add an explicit field width matching the buffer size minus one, e.g. " + fn + "(..., \"%63s\", buf) for char buf[64]. Prefer fgets() for line input.",
		CWEID:         "CWE-120",
		OWASPCategory: "A06:2021-Vulnerable and Outdated Components",
		Language:      c.language,
		Confidence:    "high",
		Tags:          []string{"buffer-overflow", "memory-safety", "libc", "ast"},
	})
}

// hasUnboundedStrConversion reports whether a scanf format string literal (with
// its surrounding quotes) contains a %s or %[ conversion lacking a numeric field
// width. `%*s` (assignment-suppressed) does not write and is ignored; `%%` is a
// literal percent and is skipped.
func hasUnboundedStrConversion(quoted string) bool {
	s := quoted
	if len(s) >= 2 && (s[0] == '"') {
		s = s[1 : len(s)-1]
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		j := i + 1
		if j >= len(s) {
			break
		}
		if s[j] == '%' { // literal "%%"
			i = j
			continue
		}
		// Skip assignment-suppression '*' — those conversions discard input.
		suppressed := false
		if s[j] == '*' {
			suppressed = true
			j++
		}
		// A field width is one or more digits. If present, the conversion is
		// bounded and safe.
		width := false
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			width = true
			j++
		}
		if j >= len(s) {
			break
		}
		if s[j] == 's' || s[j] == '[' {
			if !suppressed && !width {
				return true
			}
		}
	}
	return false
}

// --- BATOU-CAST-016: memset secret-scrub dead store (CWE-14) ----------------

// checkSecretScrub flags memset(ptr, 0, n) used to wipe a secret buffer when the
// buffer is NOT read again afterward in the same function. A compiler is free to
// remove such a "dead store" under the as-if rule, leaving the secret (key,
// password) resident in memory (CWE-14). The check is deliberately narrow:
//
//   - the fill byte (arg 1) must be a literal 0 / '\0' — a zeroing wipe, the
//     shape used to scrub secrets (not memset(buf, 'A', n) initialization);
//   - the destination identifier must be a local whose name looks secret-bearing
//     (key/pass/secret/...) OR is never referenced again before the function
//     returns. Requiring one of these keeps initialization memsets (the buffer
//     is used afterward, non-secret name) from firing.
func (c *cChecker) checkSecretScrub(n *ast.Node) {
	args := findChild(n, "argument_list")
	if args == nil {
		return
	}
	named := args.NamedChildren()
	if len(named) < 3 {
		return
	}
	// Fill byte must be a zero literal — the secret-wipe shape.
	fill := unwrapParens(named[1])
	if fill == nil || fill.Type() != "number_literal" || !isZeroLiteral(fill.Text()) {
		return
	}
	dstName := baseIdentifier(named[0])
	if dstName == "" {
		return
	}
	// Only flag when the destination looks like it holds a secret AND it is not
	// read again after this memset. Both conditions reduce noise to genuine
	// scrub-of-secret dead stores.
	if !looksSecretBuffer(dstName) {
		return
	}
	if c.identifierReadAfter(n, dstName) {
		return // buffer is used again — not a dead store
	}
	c.findings = append(c.findings, rules.Finding{
		RuleID:        "BATOU-CAST-016",
		Severity:      rules.Low,
		SeverityLabel: rules.Low.String(),
		Title:         "Secret-scrubbing memset() may be optimized away",
		Description: "memset(" + dstName + ", 0, ...) zeroes a secret-bearing buffer that is never read again. " +
			"Under the as-if rule the compiler may delete this dead store, leaving the secret (key, password, " +
			"token) resident in memory where a later disclosure can expose it (CWE-14).",
		FilePath:      c.filePath,
		LineNumber:    int(n.StartRow()) + 1,
		MatchedText:   truncate(n.Text(), 200),
		Suggestion:    "Use a wipe the compiler cannot elide: explicit_bzero() (BSD/glibc), memset_s() (C11 Annex K), or SecureZeroMemory() (Windows).",
		CWEID:         "CWE-14",
		OWASPCategory: "A04:2021-Insecure Design",
		Language:      c.language,
		Confidence:    "medium",
		Tags:          []string{"secret-scrub", "dead-store", "libc", "ast"},
	})
}

// isZeroLiteral reports whether a number_literal text represents zero
// (0, 0x0, 0L, '\0' is a char_literal handled elsewhere).
func isZeroLiteral(t string) bool {
	switch strings.TrimRight(t, "lLuU") {
	case "0", "0x0", "0X0", "00":
		return true
	}
	return false
}

// looksSecretBuffer reports whether an identifier name suggests it holds
// cryptographic or credential material that must be scrubbed.
func looksSecretBuffer(name string) bool {
	l := strings.ToLower(name)
	for _, kw := range []string{"key", "pass", "secret", "passwd", "cred", "token", "priv", "nonce", "seed", "plaintext", "session"} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

// identifierReadAfter reports whether the identifier `name` is referenced
// anywhere in the enclosing function AFTER the call node `n` (by source row).
// Used to decide whether a scrub memset is a dead store.
func (c *cChecker) identifierReadAfter(n *ast.Node, name string) bool {
	var fnDef *ast.Node
	for _, anc := range n.Ancestors() {
		if anc.Type() == "function_definition" {
			fnDef = anc
			break
		}
	}
	if fnDef == nil {
		// No enclosing function (file scope) — treat as read to stay safe.
		return true
	}
	memsetRow := n.StartRow()
	read := false
	fnDef.Walk(func(w *ast.Node) bool {
		if read {
			return false
		}
		if w.Type() == "identifier" && w.Text() == name && w.StartRow() > memsetRow {
			// Ignore the memset's own argument occurrence (same row already
			// excluded by the strict-greater comparison).
			read = true
			return false
		}
		return true
	})
	return read
}

// --- BATOU-CAST-018: /dev/random read in a loop without close (CWE-400) -----

// checkDevRandomLoop flags an open()/fopen() of the "/dev/random" path that sits
// inside a loop without a matching close in that loop body. Repeatedly opening
// /dev/random without closing exhausts file descriptors (and blocks on entropy),
// a denial-of-service (CWE-400). Called once per file from walk(); it scans loop
// bodies rather than individual calls.
func (c *cChecker) checkDevRandomLoop() {
	root := c.tree.Root()
	if root == nil {
		return
	}
	root.Walk(func(n *ast.Node) bool {
		switch n.Type() {
		case "for_statement", "while_statement", "do_statement":
		default:
			return true
		}
		body := n.ChildByFieldName("body")
		if body == nil {
			return true
		}
		openCall := devRandomOpenInBody(body)
		if openCall == nil {
			return true
		}
		if bodyHasClose(body) {
			return true // a close in the loop body means the fd is released
		}
		c.findings = append(c.findings, rules.Finding{
			RuleID:        "BATOU-CAST-018",
			Severity:      rules.Medium,
			SeverityLabel: rules.Medium.String(),
			Title:         "/dev/random opened in a loop without close (fd exhaustion)",
			Description: "A loop opens \"/dev/random\" on every iteration but never closes the descriptor in the " +
				"loop body. Each iteration leaks a file descriptor; the process eventually hits its fd limit and " +
				"can no longer open files or sockets — a denial of service (CWE-400). Reading /dev/random in a " +
				"loop also blocks on entropy.",
			FilePath:      c.filePath,
			LineNumber:    int(openCall.StartRow()) + 1,
			MatchedText:   truncate(openCall.Text(), 200),
			Suggestion:    "Open the random source once before the loop (or use getrandom()/getentropy()), and close any descriptor inside the loop before the next iteration.",
			CWEID:         "CWE-400",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Language:      c.language,
			Confidence:    "medium",
			Tags:          []string{"fd-exhaustion", "dos", "resource-leak", "ast"},
		})
		return true
	})
}

// devRandomOpenInBody returns the first open()/fopen() call in `body` whose path
// argument is the "/dev/random" string literal, or nil.
func devRandomOpenInBody(body *ast.Node) *ast.Node {
	var found *ast.Node
	body.Walk(func(w *ast.Node) bool {
		if found != nil {
			return false
		}
		if w.Type() != "call_expression" {
			return true
		}
		fn := cCallName(w)
		if fn != "open" && fn != "fopen" && fn != "open64" {
			return true
		}
		// Path is the first argument for both open and fopen.
		if arg0 := callArgText(w, 0); strings.Contains(arg0, "/dev/random") {
			found = w
			return false
		}
		return true
	})
	return found
}

// bodyHasClose reports whether a loop body contains a close()/fclose() call.
func bodyHasClose(body *ast.Node) bool {
	found := false
	body.Walk(func(w *ast.Node) bool {
		if found {
			return false
		}
		if w.Type() == "call_expression" {
			switch cCallName(w) {
			case "close", "fclose":
				found = true
				return false
			}
		}
		return true
	})
	return found
}
