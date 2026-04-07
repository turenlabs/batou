#!/usr/bin/env python3
"""Generate Go rule files and taint catalog entries for Batou from YAML definitions.

Usage:
    python tools/generate_rules.py rules.yaml              # generate + verify
    python tools/generate_rules.py --dry-run rules.yaml    # preview only
    python tools/generate_rules.py --no-verify rules.yaml  # skip go build
"""

import argparse
import os
import re
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants & mappings
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

SEVERITY_MAP = {
    "info": "rules.Info",
    "low": "rules.Low",
    "medium": "rules.Medium",
    "high": "rules.High",
    "critical": "rules.Critical",
}

LANGUAGE_MAP = {
    "go": "rules.LangGo",
    "python": "rules.LangPython",
    "javascript": "rules.LangJavaScript",
    "typescript": "rules.LangTypeScript",
    "java": "rules.LangJava",
    "ruby": "rules.LangRuby",
    "php": "rules.LangPHP",
    "csharp": "rules.LangCSharp",
    "kotlin": "rules.LangKotlin",
    "groovy": "rules.LangGroovy",
    "swift": "rules.LangSwift",
    "rust": "rules.LangRust",
    "c": "rules.LangC",
    "cpp": "rules.LangCPP",
    "shell": "rules.LangShell",
    "sql": "rules.LangSQL",
    "yaml": "rules.LangYAML",
    "json": "rules.LangJSON",
    "perl": "rules.LangPerl",
    "lua": "rules.LangLua",
    "dockerfile": "rules.LangDocker",
    "terraform": "rules.LangTerraform",
    "*": "rules.LangAny",
}

SOURCE_CATEGORY_MAP = {
    "user_input": "taint.SrcUserInput",
    "network": "taint.SrcNetwork",
    "file_read": "taint.SrcFileRead",
    "env_var": "taint.SrcEnvVar",
    "database": "taint.SrcDatabase",
    "deserialized": "taint.SrcDeserialized",
    "cli_arg": "taint.SrcCLIArg",
    "external": "taint.SrcExternal",
}

SINK_CATEGORY_MAP = {
    "sql_query": "taint.SnkSQLQuery",
    "command_exec": "taint.SnkCommand",
    "file_write": "taint.SnkFileWrite",
    "html_output": "taint.SnkHTMLOutput",
    "code_eval": "taint.SnkEval",
    "redirect": "taint.SnkRedirect",
    "ldap_query": "taint.SnkLDAP",
    "xpath_query": "taint.SnkXPath",
    "http_header": "taint.SnkHeader",
    "template_render": "taint.SnkTemplate",
    "deserialize": "taint.SnkDeserialize",
    "log_output": "taint.SnkLog",
    "crypto_input": "taint.SnkCrypto",
    "url_fetch": "taint.SnkURLFetch",
}

# ID prefix → category mapping (for scanning existing rules)
KNOWN_PREFIXES = {
    "INJ": "injection", "SEC": "secrets", "CRYPTO": "crypto", "XSS": "xss",
    "TRAV": "traversal", "SSRF": "ssrf", "AUTH": "auth", "GEN": "generic",
    "LOG": "logging", "VAL": "validation", "MEM": "memory", "NOSQL": "nosql",
    "XXE": "xxe", "REDIR": "redirect", "GQL": "graphql", "MISC": "misconfig",
    "DESER": "deser", "FW": "framework", "PROTO": "prototype",
    "MASSASGN": "massassign", "CORS": "cors", "HDR": "header",
    "ENC": "encoding", "CTR": "container", "SSTI": "ssti", "JWT": "jwt",
    "SESS": "session", "UPLOAD": "upload", "RACE": "race", "WS": "websocket",
    "OAUTH": "oauth", "KT": "kotlin", "GVY": "groovy", "PL": "perl",
    "LUA": "lua", "SWIFT": "swift", "CS": "csharp", "RS": "rust",
    "PHP": "php", "RB": "ruby", "PY": "python", "JAVA": "java",
    "JSTS": "jsts", "GO": "golang",
}

# RE2-incompatible constructs (Go's regexp engine)
RE2_FORBIDDEN = [
    (r"\(\?!", "negative lookahead (?!)"),
    (r"\(\?<!", "negative lookbehind (?<!)"),
    (r"\(\?<=", "positive lookbehind (?<=)"),
    (r"\(\?=", "positive lookahead (?=)"),
    (r"\(\?>", "atomic group (?>)"),
    (r"\\p\{", "Unicode property (\\p{...}) — use character classes instead"),
]

# Catalog struct names per language
CATALOG_STRUCT_MAP = {
    "go": "GoCatalog",
    "python": "PythonCatalog",
    "javascript": "JavaScriptCatalog",
    "typescript": "TypeScriptCatalog",
    "java": "JavaCatalog",
    "ruby": "RubyCatalog",
    "php": "PHPCatalog",
    "csharp": "CSharpCatalog",
    "kotlin": "KotlinCatalog",
    "groovy": "GroovyCatalog",
    "swift": "SwiftCatalog",
    "rust": "RustCatalog",
    "c": "CCatalog",
    "cpp": "CppCatalog",
    "perl": "PerlCatalog",
    "lua": "LuaCatalog",
}

# Language constant names for taint catalog files
LANG_CONST_MAP = {
    "go": "rules.LangGo",
    "python": "rules.LangPython",
    "javascript": "rules.LangJavaScript",
    "typescript": "rules.LangTypeScript",
    "java": "rules.LangJava",
    "ruby": "rules.LangRuby",
    "php": "rules.LangPHP",
    "csharp": "rules.LangCSharp",
    "kotlin": "rules.LangKotlin",
    "groovy": "rules.LangGroovy",
    "swift": "rules.LangSwift",
    "rust": "rules.LangRust",
    "c": "rules.LangC",
    "cpp": "rules.LangCPP",
    "perl": "rules.LangPerl",
    "lua": "rules.LangLua",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PatternDef:
    regex: str
    confidence: str = "high"
    description: str = ""
    language: str = "*"


@dataclass
class RuleDef:
    category: str
    id_prefix: str
    struct_name: str
    name: str
    description: str
    severity: str
    cwe: str = ""
    owasp: str = ""
    languages: list = field(default_factory=lambda: ["*"])
    tags: list = field(default_factory=list)
    suggestion: str = ""
    patterns: list = field(default_factory=list)
    safe_patterns: list = field(default_factory=list)
    # Assigned during generation
    rule_id: str = ""


@dataclass
class TaintSourceDef:
    id: str
    category: str
    pattern: str
    object_type: str = ""
    method_name: str = ""
    description: str = ""
    assigns: str = "return"


@dataclass
class TaintSinkDef:
    id: str
    category: str
    pattern: str
    object_type: str = ""
    method_name: str = ""
    dangerous_args: list = field(default_factory=lambda: [0])
    severity: str = "high"
    description: str = ""
    cwe: str = ""
    owasp: str = ""


@dataclass
class TaintSanitizerDef:
    id: str
    pattern: str
    method_name: str = ""
    neutralizes: list = field(default_factory=list)
    description: str = ""
    object_type: str = ""


@dataclass
class TaintEntryGroup:
    language: str
    sources: list = field(default_factory=list)
    sinks: list = field(default_factory=list)
    sanitizers: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# YAML parsing & validation
# ---------------------------------------------------------------------------

def parse_yaml(path: str) -> dict:
    """Parse and validate the YAML definition file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("YAML root must be a mapping")

    rules_list = []
    for i, r in enumerate(data.get("rules", [])):
        patterns = []
        for p in r.get("patterns", []):
            patterns.append(PatternDef(
                regex=p["regex"],
                confidence=p.get("confidence", "high"),
                description=p.get("description", ""),
                language=p.get("language", "*"),
            ))
        rules_list.append(RuleDef(
            category=r["category"],
            id_prefix=r["id_prefix"],
            struct_name=r["struct_name"],
            name=r["name"],
            description=r["description"],
            severity=r["severity"],
            cwe=r.get("cwe", ""),
            owasp=r.get("owasp", ""),
            languages=r.get("languages", ["*"]),
            tags=r.get("tags", []),
            suggestion=r.get("suggestion", ""),
            patterns=patterns,
            safe_patterns=r.get("safe_patterns", []),
        ))

    taint_entries = []
    for t in data.get("taint_entries", []):
        sources = [TaintSourceDef(**s) for s in t.get("sources", [])]
        sinks = [TaintSinkDef(**s) for s in t.get("sinks", [])]
        sanitizers = [TaintSanitizerDef(**s) for s in t.get("sanitizers", [])]
        taint_entries.append(TaintEntryGroup(
            language=t["language"],
            sources=sources,
            sinks=sinks,
            sanitizers=sanitizers,
        ))

    return {"rules": rules_list, "taint_entries": taint_entries}


# ---------------------------------------------------------------------------
# RE2 regex validation
# ---------------------------------------------------------------------------

def validate_re2(pattern: str, context: str = "") -> list[str]:
    """Check a regex pattern for RE2 compatibility. Returns list of errors."""
    errors = []
    for forbidden, desc in RE2_FORBIDDEN:
        if forbidden in pattern:
            errors.append(f"RE2-incompatible construct in {context}: {desc} in pattern: {pattern}")

    # Try compiling as Python regex (catches basic syntax errors)
    try:
        re.compile(pattern)
    except re.error as e:
        errors.append(f"Invalid regex in {context}: {e} in pattern: {pattern}")

    return errors


# ---------------------------------------------------------------------------
# ID scanner
# ---------------------------------------------------------------------------

def find_max_id(prefix: str) -> int:
    """Scan existing rules to find the max ID number for a given prefix."""
    rules_dir = PROJECT_ROOT / "internal" / "rules"
    pattern = re.compile(rf'BATOU-{re.escape(prefix)}-(\d+)')
    max_id = 0

    for go_file in rules_dir.rglob("*.go"):
        try:
            content = go_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        for match in pattern.finditer(content):
            num = int(match.group(1))
            if num > max_id:
                max_id = num

    return max_id


# ---------------------------------------------------------------------------
# Rule file generator
# ---------------------------------------------------------------------------

def _go_string(s: str) -> str:
    """Escape a string for Go source code."""
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _go_raw_string(s: str) -> str:
    """Return a Go raw string literal. Falls back to interpreted if backtick present."""
    if "`" in s:
        return '"' + _go_string(s) + '"'
    return "`" + s + "`"


def _var_name(struct_name: str, idx: int, desc: str) -> str:
    """Generate a regex var name like: patHTMLInjection0."""
    return f"pat{struct_name}{idx}"


def _check_existing_helpers(category_dir: Path) -> tuple[bool, bool]:
    """Check if isComment and truncate helpers already exist in the package.

    Returns (has_isComment, has_truncate).
    """
    has_is_comment = False
    has_truncate = False

    if not category_dir.exists():
        return False, False

    for go_file in category_dir.glob("*.go"):
        if go_file.name.endswith("_test.go") or go_file.name.endswith("_gen.go"):
            continue
        try:
            content = go_file.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        if re.search(r'^func isComment\(', content, re.MULTILINE):
            has_is_comment = True
        if re.search(r'^func truncate\(', content, re.MULTILINE):
            has_truncate = True

    return has_is_comment, has_truncate


def generate_rule_file(rule_defs: list[RuleDef], category: str, is_new_category: bool) -> str:
    """Generate Go source for a list of rules in the same category."""
    category_dir = PROJECT_ROOT / "internal" / "rules" / category

    lines = []
    lines.append(f"// Code generated by tools/generate_rules.py; DO NOT EDIT.")
    lines.append(f"")
    lines.append(f"package {category}")
    lines.append(f"")
    lines.append(f"import (")
    lines.append(f'\t"regexp"')
    lines.append(f'\t"strings"')
    lines.append(f"")
    lines.append(f'\t"github.com/turenlabs/batou/internal/rules"')
    lines.append(f")")
    lines.append(f"")

    # Compiled regex vars
    lines.append(f"// --- Compiled patterns ---")
    lines.append(f"")
    lines.append(f"var (")
    for rule_def in rule_defs:
        for i, pat in enumerate(rule_def.patterns):
            vname = _var_name(rule_def.struct_name, i, pat.description)
            comment = f" // {pat.description}" if pat.description else ""
            lines.append(f"\t{vname} = regexp.MustCompile({_go_raw_string(pat.regex)}){comment}")
        if rule_def.safe_patterns:
            for j, sp in enumerate(rule_def.safe_patterns):
                lines.append(f"\tsafe{rule_def.struct_name}{j} = regexp.MustCompile({_go_raw_string(sp)})")
    lines.append(f")")
    lines.append(f"")

    # init() registration
    lines.append(f"func init() {{")
    for rule_def in rule_defs:
        lines.append(f"\trules.Register(&{rule_def.struct_name}{{}})")
    lines.append(f"}}")
    lines.append(f"")

    # Generate each rule struct + methods
    for rule_def in rule_defs:
        lines.extend(_generate_rule_struct(rule_def))
        lines.append(f"")

    # Helper functions — check what already exists in the package
    has_is_comment, has_truncate = _check_existing_helpers(category_dir)
    need_is_comment = not has_is_comment
    need_truncate = not has_truncate

    if need_is_comment or need_truncate:
        lines.append("// --- Helpers ---")
        lines.append("")
        if need_is_comment:
            lines.extend([
                "func isComment(line string) bool {",
                '\treturn strings.HasPrefix(line, "//") ||',
                '\t\tstrings.HasPrefix(line, "#") ||',
                '\t\tstrings.HasPrefix(line, "*") ||',
                '\t\tstrings.HasPrefix(line, "/*") ||',
                '\t\tstrings.HasPrefix(line, "<!--")',
                "}",
                "",
            ])
        if need_truncate:
            lines.extend([
                "func truncate(s string, maxLen int) string {",
                "\tif len(s) > maxLen {",
                '\t\treturn s[:maxLen] + "..."',
                "\t}",
                "\treturn s",
                "}",
                "",
            ])

    return "\n".join(lines) + "\n"


def _generate_rule_struct(rule_def: RuleDef) -> list[str]:
    """Generate a single rule struct with all interface methods."""
    sn = rule_def.struct_name
    rid = rule_def.rule_id

    # Languages slice
    lang_items = ", ".join(LANGUAGE_MAP[l] for l in rule_def.languages)
    # Tags slice
    tags_items = ", ".join(f'"{t}"' for t in rule_def.tags) if rule_def.tags else ""

    sev = SEVERITY_MAP.get(rule_def.severity.lower(), "rules.Medium")

    lines = []
    lines.append(f"// --- {rid}: {rule_def.name} ---")
    lines.append(f"")
    lines.append(f"type {sn} struct{{}}")
    lines.append(f"")
    lines.append(f'func (r *{sn}) ID() string                        {{ return "{rid}" }}')
    lines.append(f'func (r *{sn}) Name() string                      {{ return "{sn}" }}')
    lines.append(f"func (r *{sn}) DefaultSeverity() rules.Severity   {{ return {sev} }}")
    lines.append(f"func (r *{sn}) Languages() []rules.Language {{")
    lines.append(f"\treturn []rules.Language{{{lang_items}}}")
    lines.append(f"}}")
    lines.append(f"")
    lines.append(f"func (r *{sn}) Description() string {{")
    lines.append(f'\treturn "{_go_string(rule_def.description)}"')
    lines.append(f"}}")
    lines.append(f"")

    # Scan method
    lines.append(f"func (r *{sn}) Scan(ctx *rules.ScanContext) []rules.Finding {{")
    lines.append(f"\tvar findings []rules.Finding")
    lines.append(f'\tlines := strings.Split(ctx.Content, "\\n")')
    lines.append(f"")

    # Safe pattern pre-check
    if rule_def.safe_patterns:
        conditions = []
        for j in range(len(rule_def.safe_patterns)):
            conditions.append(f"safe{sn}{j}.MatchString(ctx.Content)")
        lines.append(f"\t// Suppress if safe pattern present")
        lines.append(f"\tif {' || '.join(conditions)} {{")
        lines.append(f"\t\treturn findings")
        lines.append(f"\t}}")
        lines.append(f"")

    lines.append(f"\tfor i, line := range lines {{")
    lines.append(f"\t\tlineNum := i + 1")
    lines.append(f"\t\ttrimmed := strings.TrimSpace(line)")
    lines.append(f"")
    lines.append(f"\t\tif isComment(trimmed) {{")
    lines.append(f"\t\t\tcontinue")
    lines.append(f"\t\t}}")
    lines.append(f"")
    lines.append(f"\t\tvar matched string")
    lines.append(f'\t\tconfidence := "high"')
    lines.append(f"")

    # Check each pattern
    for i, pat in enumerate(rule_def.patterns):
        vname = _var_name(sn, i, pat.description)
        if pat.language == "*":
            lines.append(f"\t\tif loc := {vname}.FindString(line); loc != \"\" {{")
            lines.append(f"\t\t\tmatched = loc")
            if pat.confidence != "high":
                lines.append(f'\t\t\tconfidence = "{pat.confidence}"')
            lines.append(f"\t\t}}")
        else:
            lang_const = LANGUAGE_MAP.get(pat.language, "rules.LangAny")
            lines.append(f"\t\tif ctx.Language == {lang_const} {{")
            lines.append(f"\t\t\tif loc := {vname}.FindString(line); loc != \"\" {{")
            lines.append(f"\t\t\t\tmatched = loc")
            if pat.confidence != "high":
                lines.append(f'\t\t\t\tconfidence = "{pat.confidence}"')
            lines.append(f"\t\t\t}}")
            lines.append(f"\t\t}}")

    lines.append(f"")
    lines.append(f"\t\tif matched != \"\" {{")

    # Build the finding
    title = rule_def.name
    desc = _go_string(rule_def.description)
    suggestion = _go_string(rule_def.suggestion) if rule_def.suggestion else ""

    lines.append(f"\t\t\tfindings = append(findings, rules.Finding{{")
    lines.append(f'\t\t\t\tRuleID:        r.ID(),')
    lines.append(f'\t\t\t\tSeverity:      r.DefaultSeverity(),')
    lines.append(f'\t\t\t\tSeverityLabel: r.DefaultSeverity().String(),')
    lines.append(f'\t\t\t\tTitle:         "{_go_string(title)}",')
    lines.append(f'\t\t\t\tDescription:   "{desc}",')
    lines.append(f'\t\t\t\tFilePath:      ctx.FilePath,')
    lines.append(f'\t\t\t\tLineNumber:    lineNum,')
    lines.append(f'\t\t\t\tMatchedText:   truncate(matched, 120),')
    if suggestion:
        lines.append(f'\t\t\t\tSuggestion:    "{suggestion}",')
    if rule_def.cwe:
        lines.append(f'\t\t\t\tCWEID:         "{rule_def.cwe}",')
    if rule_def.owasp:
        lines.append(f'\t\t\t\tOWASPCategory: "{rule_def.owasp}",')
    lines.append(f'\t\t\t\tLanguage:      ctx.Language,')
    lines.append(f'\t\t\t\tConfidence:    confidence,')
    if tags_items:
        lines.append(f'\t\t\t\tTags:          []string{{{tags_items}}},')
    lines.append(f"\t\t\t}})")
    lines.append(f"\t\t}}")
    lines.append(f"\t}}")
    lines.append(f"")
    lines.append(f"\treturn findings")
    lines.append(f"}}")

    return lines


# ---------------------------------------------------------------------------
# Taint catalog generator
# ---------------------------------------------------------------------------

def _format_source_entry(src: TaintSourceDef, lang: str) -> str:
    """Format a single taint.SourceDef Go struct literal."""
    lang_const = LANG_CONST_MAP.get(lang, "rules.LangPython")
    cat = SOURCE_CATEGORY_MAP.get(src.category, "taint.SrcExternal")
    return textwrap.dedent(f"""\
\t\t{{
\t\t\tID:          "{src.id}",
\t\t\tCategory:    {cat},
\t\t\tLanguage:    {lang_const},
\t\t\tPattern:     {_go_raw_string(src.pattern)},
\t\t\tObjectType:  "{_go_string(src.object_type)}",
\t\t\tMethodName:  "{_go_string(src.method_name)}",
\t\t\tDescription: "{_go_string(src.description)}",
\t\t\tAssigns:     "{src.assigns}",
\t\t}},""")


def _format_sink_entry(sink: TaintSinkDef, lang: str) -> str:
    """Format a single taint.SinkDef Go struct literal."""
    lang_const = LANG_CONST_MAP.get(lang, "rules.LangPython")
    cat = SINK_CATEGORY_MAP.get(sink.category, "taint.SnkSQLQuery")
    sev = SEVERITY_MAP.get(sink.severity.lower(), "rules.High")
    args = ", ".join(str(a) for a in sink.dangerous_args)
    return textwrap.dedent(f"""\
\t\t{{
\t\t\tID:            "{sink.id}",
\t\t\tCategory:      {cat},
\t\t\tLanguage:      {lang_const},
\t\t\tPattern:       {_go_raw_string(sink.pattern)},
\t\t\tObjectType:    "{_go_string(sink.object_type)}",
\t\t\tMethodName:    "{_go_string(sink.method_name)}",
\t\t\tDangerousArgs: []int{{{args}}},
\t\t\tSeverity:      {sev},
\t\t\tDescription:   "{_go_string(sink.description)}",
\t\t\tCWEID:         "{sink.cwe}",
\t\t\tOWASPCategory: "{sink.owasp}",
\t\t}},""")


def _format_sanitizer_entry(san: TaintSanitizerDef, lang: str) -> str:
    """Format a single taint.SanitizerDef Go struct literal."""
    lang_const = LANG_CONST_MAP.get(lang, "rules.LangPython")
    neutralizes = ", ".join(
        SINK_CATEGORY_MAP.get(n, f"taint.SinkCategory(\"{n}\")")
        for n in san.neutralizes
    )
    return textwrap.dedent(f"""\
\t\t{{
\t\t\tID:          "{san.id}",
\t\t\tLanguage:    {lang_const},
\t\t\tPattern:     {_go_raw_string(san.pattern)},
\t\t\tObjectType:  "{_go_string(san.object_type)}",
\t\t\tMethodName:  "{_go_string(san.method_name)}",
\t\t\tNeutralizes: []taint.SinkCategory{{{neutralizes}}},
\t\t\tDescription: "{_go_string(san.description)}",
\t\t}},""")


def _insert_into_slice(file_path: Path, entries_text: str) -> str:
    """Insert new entries before the closing of the return slice in a Go file.

    Finds the return []Type{ ... } and inserts before the final '}'.
    Returns the modified file content.
    """
    content = file_path.read_text()

    # Find the last closing brace+comma that ends the return slice.
    # We look for the pattern: a line that is just "\t}" (one tab + closing brace)
    # preceded by "\t\t}," lines (struct entries). The return statement ends
    # with "\t}\n}" where the outer "}" closes the function.
    #
    # Strategy: find "return []taint." to locate the function, then find the
    # matching closing. We insert just before the slice's closing "}\n}".

    # Find the return statement
    return_match = re.search(r'return \[\]taint\.\w+Def\{', content)
    if not return_match:
        raise ValueError(f"Cannot find return []taint.*Def{{ in {file_path}")

    # From the return statement, track brace depth to find the closing
    start = return_match.start()
    # Find the opening brace of the slice literal
    brace_start = content.index("{", return_match.start())
    depth = 0
    insert_pos = -1
    for pos in range(brace_start, len(content)):
        ch = content[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                insert_pos = pos
                break

    if insert_pos == -1:
        raise ValueError(f"Cannot find closing brace of return slice in {file_path}")

    # Insert the new entries with a blank line separator before the closing
    comment = "\n\t\t// --- Generated entries ---"
    new_content = content[:insert_pos] + comment + "\n" + entries_text + "\n\t" + content[insert_pos:]
    return new_content


def generate_taint_entries(entry_group: TaintEntryGroup, dry_run: bool) -> list[str]:
    """Generate or insert taint catalog entries for a language.

    Returns list of files created/modified.
    """
    lang = entry_group.language
    lang_dir = PROJECT_ROOT / "internal" / "taint" / "languages"
    modified_files = []

    # Check if catalog exists
    catalog_file = lang_dir / f"{lang}_catalog.go"
    is_new_lang = not catalog_file.exists()

    if is_new_lang:
        # Generate all 4 files for a new language
        modified_files.extend(_generate_new_catalog(entry_group, lang_dir, dry_run))
    else:
        # Insert into existing files
        if entry_group.sources:
            src_file = lang_dir / f"{lang}_sources.go"
            entries = "\n".join(_format_source_entry(s, lang) for s in entry_group.sources)
            if dry_run:
                print(f"\n[DRY RUN] Would insert into {src_file}:")
                print(entries)
            else:
                new_content = _insert_into_slice(src_file, entries)
                src_file.write_text(new_content)
                modified_files.append(str(src_file))

        if entry_group.sinks:
            sink_file = lang_dir / f"{lang}_sinks.go"
            entries = "\n".join(_format_sink_entry(s, lang) for s in entry_group.sinks)
            if dry_run:
                print(f"\n[DRY RUN] Would insert into {sink_file}:")
                print(entries)
            else:
                new_content = _insert_into_slice(sink_file, entries)
                sink_file.write_text(new_content)
                modified_files.append(str(sink_file))

        if entry_group.sanitizers:
            san_file = lang_dir / f"{lang}_sanitizers.go"
            entries = "\n".join(_format_sanitizer_entry(s, lang) for s in entry_group.sanitizers)
            if dry_run:
                print(f"\n[DRY RUN] Would insert into {san_file}:")
                print(entries)
            else:
                new_content = _insert_into_slice(san_file, entries)
                san_file.write_text(new_content)
                modified_files.append(str(san_file))

    return modified_files


def _generate_new_catalog(entry_group: TaintEntryGroup, lang_dir: Path, dry_run: bool) -> list[str]:
    """Generate all 4 catalog files for a brand-new language."""
    lang = entry_group.language
    struct_name = CATALOG_STRUCT_MAP.get(lang)
    if not struct_name:
        # Auto-generate: capitalize first letter + "Catalog"
        struct_name = lang.capitalize() + "Catalog"

    lang_const = LANG_CONST_MAP.get(lang)
    if not lang_const:
        raise ValueError(f"Unknown language '{lang}' — add it to LANG_CONST_MAP")

    files = []

    # 1. Catalog file
    catalog_content = textwrap.dedent(f"""\
        // Code generated by tools/generate_rules.py; DO NOT EDIT.

        package languages

        import (
        \t"github.com/turenlabs/batou/internal/rules"
        \t"github.com/turenlabs/batou/internal/taint"
        )

        type {struct_name} struct{{}}

        func init() {{
        \ttaint.RegisterCatalog(&{struct_name}{{}})
        }}

        func (c *{struct_name}) Language() rules.Language {{
        \treturn {lang_const}
        }}
    """)

    # 2. Sources file
    source_entries = "\n".join(_format_source_entry(s, lang) for s in entry_group.sources)
    sources_content = textwrap.dedent(f"""\
        // Code generated by tools/generate_rules.py; DO NOT EDIT.

        package languages

        import (
        \t"github.com/turenlabs/batou/internal/rules"
        \t"github.com/turenlabs/batou/internal/taint"
        )

        func (c *{struct_name}) Sources() []taint.SourceDef {{
        \treturn []taint.SourceDef{{
    """) + source_entries + "\n\t}\n}\n"

    # 3. Sinks file
    sink_entries = "\n".join(_format_sink_entry(s, lang) for s in entry_group.sinks)
    sinks_content = textwrap.dedent(f"""\
        // Code generated by tools/generate_rules.py; DO NOT EDIT.

        package languages

        import (
        \t"github.com/turenlabs/batou/internal/rules"
        \t"github.com/turenlabs/batou/internal/taint"
        )

        func (c *{struct_name}) Sinks() []taint.SinkDef {{
        \treturn []taint.SinkDef{{
    """) + sink_entries + "\n\t}\n}\n"

    # 4. Sanitizers file
    san_entries = "\n".join(_format_sanitizer_entry(s, lang) for s in entry_group.sanitizers)
    sanitizers_content = textwrap.dedent(f"""\
        // Code generated by tools/generate_rules.py; DO NOT EDIT.

        package languages

        import (
        \t"github.com/turenlabs/batou/internal/rules"
        \t"github.com/turenlabs/batou/internal/taint"
        )

        func (c *{struct_name}) Sanitizers() []taint.SanitizerDef {{
        \treturn []taint.SanitizerDef{{
    """) + san_entries + "\n\t}\n}\n"

    file_map = {
        f"{lang}_catalog.go": catalog_content,
        f"{lang}_sources.go": sources_content,
        f"{lang}_sinks.go": sinks_content,
        f"{lang}_sanitizers.go": sanitizers_content,
    }

    for fname, content in file_map.items():
        fpath = lang_dir / fname
        if dry_run:
            print(f"\n[DRY RUN] Would create {fpath}:")
            print(content[:500] + ("..." if len(content) > 500 else ""))
        else:
            fpath.write_text(content)
            files.append(str(fpath))

    return files


# ---------------------------------------------------------------------------
# main.go import updater
# ---------------------------------------------------------------------------

def update_main_imports(categories: set[str], dry_run: bool) -> bool:
    """Add blank imports to cmd/batou/main.go for new rule categories.

    Returns True if the file was modified.
    """
    main_go = PROJECT_ROOT / "cmd" / "batou" / "main.go"
    content = main_go.read_text()

    new_imports = []
    for cat in sorted(categories):
        import_path = f'_ "github.com/turenlabs/batou/internal/rules/{cat}"'
        if import_path not in content:
            new_imports.append(f"\t{import_path}")

    if not new_imports:
        return False

    # Find the last rule import line to insert after
    lines = content.split("\n")
    insert_idx = -1
    for i, line in enumerate(lines):
        if '_ "github.com/turenlabs/batou/internal/rules/' in line:
            insert_idx = i

    if insert_idx == -1:
        print("WARNING: Could not find rule imports in main.go — skipping import update", file=sys.stderr)
        return False

    if dry_run:
        print(f"\n[DRY RUN] Would add imports to {main_go}:")
        for imp in new_imports:
            print(f"  {imp}")
        return True

    # Insert after the last rule import
    for j, imp in enumerate(new_imports):
        lines.insert(insert_idx + 1 + j, imp)

    main_go.write_text("\n".join(lines))
    return True


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def run_gofmt(files: list[str]) -> bool:
    """Run gofmt -w on generated files. Returns True on success."""
    if not files:
        return True
    try:
        result = subprocess.run(
            ["gofmt", "-w"] + files,
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
        )
        if result.returncode != 0:
            print(f"gofmt errors:\n{result.stderr}", file=sys.stderr)
            return False
        return True
    except FileNotFoundError:
        print("WARNING: gofmt not found — skipping formatting", file=sys.stderr)
        return True


def run_go_build() -> bool:
    """Run go build ./... to verify generated code compiles."""
    print("Running go build ./... to verify...")
    try:
        result = subprocess.run(
            ["go", "build", "./..."],
            capture_output=True, text=True,
            cwd=str(PROJECT_ROOT),
            env={**os.environ, "CGO_ENABLED": "1"},
        )
        if result.returncode != 0:
            print(f"go build FAILED:\n{result.stderr}", file=sys.stderr)
            return False
        print("go build passed.")
        return True
    except FileNotFoundError:
        print("WARNING: go not found — skipping build verification", file=sys.stderr)
        return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate Batou rule files and taint catalog entries from YAML definitions.",
    )
    parser.add_argument("yaml_file", help="Path to YAML definition file")
    parser.add_argument("--dry-run", action="store_true", help="Preview generated output without writing files")
    parser.add_argument("--no-verify", action="store_true", help="Skip go build verification")
    args = parser.parse_args()

    # Parse YAML
    print(f"Parsing {args.yaml_file}...")
    data = parse_yaml(args.yaml_file)

    rule_defs = data["rules"]
    taint_entries = data["taint_entries"]

    if not rule_defs and not taint_entries:
        print("No rules or taint entries defined — nothing to generate.")
        return

    # Validate all regex patterns
    errors = []
    for rd in rule_defs:
        for pat in rd.patterns:
            errors.extend(validate_re2(pat.regex, f"rule {rd.struct_name}"))
        for sp in rd.safe_patterns:
            errors.extend(validate_re2(sp, f"safe_pattern in {rd.struct_name}"))
    for te in taint_entries:
        for src in te.sources:
            errors.extend(validate_re2(src.pattern, f"taint source {src.id}"))
        for sink in te.sinks:
            errors.extend(validate_re2(sink.pattern, f"taint sink {sink.id}"))
        for san in te.sanitizers:
            errors.extend(validate_re2(san.pattern, f"taint sanitizer {san.id}"))

    if errors:
        print("Regex validation errors:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)

    print(f"All regex patterns are RE2-compatible.")

    # Assign IDs to rules
    for rd in rule_defs:
        max_existing = find_max_id(rd.id_prefix)
        rd.rule_id = f"BATOU-{rd.id_prefix}-{max_existing + 1:03d}"
        print(f"  Rule {rd.struct_name}: assigned {rd.rule_id}")

    # Group rules by category
    rules_by_category: dict[str, list[RuleDef]] = {}
    for rd in rule_defs:
        rules_by_category.setdefault(rd.category, []).append(rd)

    all_modified_files = []
    new_categories = set()

    # Generate rule files
    for category, cat_rules in rules_by_category.items():
        rules_dir = PROJECT_ROOT / "internal" / "rules" / category
        is_new_category = not rules_dir.exists()

        if is_new_category:
            new_categories.add(category)
            if not args.dry_run:
                rules_dir.mkdir(parents=True, exist_ok=True)

        # Determine output filename
        if is_new_category:
            out_file = rules_dir / f"{category}.go"
        else:
            out_file = rules_dir / f"{category}_gen.go"

        go_source = generate_rule_file(cat_rules, category, is_new_category)

        if args.dry_run:
            print(f"\n[DRY RUN] Would write {out_file}:")
            print(go_source)
        else:
            out_file.write_text(go_source)
            all_modified_files.append(str(out_file))
            print(f"  Generated {out_file}")

    # Generate taint entries
    for te in taint_entries:
        modified = generate_taint_entries(te, args.dry_run)
        all_modified_files.extend(modified)
        if modified:
            print(f"  Updated taint catalog for {te.language}: {len(modified)} files")

    # Update main.go imports for new categories
    if new_categories:
        updated = update_main_imports(new_categories, args.dry_run)
        if updated and not args.dry_run:
            all_modified_files.append(str(PROJECT_ROOT / "cmd" / "batou" / "main.go"))
            print(f"  Updated main.go with {len(new_categories)} new import(s)")

    if args.dry_run:
        print("\n[DRY RUN] No files were modified.")
        return

    # Run gofmt
    if all_modified_files:
        print(f"\nFormatting {len(all_modified_files)} file(s) with gofmt...")
        if not run_gofmt(all_modified_files):
            sys.exit(1)

    # Run go build
    if not args.no_verify:
        if not run_go_build():
            sys.exit(1)
    else:
        print("Skipping go build verification (--no-verify).")

    print(f"\nDone! Generated/modified {len(all_modified_files)} file(s).")


if __name__ == "__main__":
    main()
