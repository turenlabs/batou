package deser

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// Compiled regex patterns for extended deserialization detection
// ---------------------------------------------------------------------------

var (
	// BATOU-DESER-005: Java ObjectInputStream.readObject without filter
	reExtObjInputStream  = regexp.MustCompile(`\bObjectInputStream\s*\(`)
	reExtReadObject      = regexp.MustCompile(`\.readObject\s*\(`)
	reExtObjectFilter    = regexp.MustCompile(`(?i)(?:setObjectInputFilter|ObjectInputFilter|serialFilter|ClassFilter|lookAheadObjectInputStream|SafeObjectInputStream|ValidatingObjectInputStream)`)

	// BATOU-DESER-006: PHP unserialize with user input
	reExtPHPUnserialize    = regexp.MustCompile(`\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input|data|body|payload|param|value|raw)`)
	reExtPHPUnserializeGen = regexp.MustCompile(`\bunserialize\s*\(\s*\$[a-zA-Z_]\w*`)
	reExtPHPUserSource     = regexp.MustCompile(`\$_(?:GET|POST|REQUEST|COOKIE)|file_get_contents\s*\(\s*['"]php://input|json_decode`)

	// BATOU-DESER-007: Python yaml.load without SafeLoader
	reExtYAMLLoad      = regexp.MustCompile(`\byaml\.(?:load|unsafe_load)\s*\(`)
	reExtYAMLSafeLoad  = regexp.MustCompile(`\byaml\.(?:safe_load|load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)`)
	reExtYAMLFullLoad  = regexp.MustCompile(`\byaml\.(?:full_load|load\s*\([^)]*Loader\s*=\s*(?:yaml\.)?FullLoader)`)

	// BATOU-DESER-008: .NET BinaryFormatter deserialization
	reExtBinaryFormatter = regexp.MustCompile(`\bBinaryFormatter\s*\(\s*\)`)
	reExtBinaryDeser     = regexp.MustCompile(`\.Deserialize\s*\(`)
	reExtDotNetUnsafe    = regexp.MustCompile(`(?:LosFormatter|SoapFormatter|NetDataContractSerializer|ObjectStateFormatter|JavaScriptSerializer)\s*\(`)

	// BATOU-DESER-009: Ruby Marshal.load with untrusted data
	reExtRubyMarshalLoad = regexp.MustCompile(`\bMarshal\.(?:load|restore)\s*\(`)
	reExtRubyMarshalUser = regexp.MustCompile(`\bMarshal\.(?:load|restore)\s*\(\s*(?:params|request|session|cookies|Base64\.decode|File\.read|IO\.read)`)

	// BATOU-DESER-010: Node.js node-serialize/serialize-javascript RCE
	reExtNodeSerialize    = regexp.MustCompile(`\b(?:node-serialize|serialize|unserialize)\s*\.\s*unserialize\s*\(`)
	reExtNodeSerializeReq = regexp.MustCompile(`(?i)(?:serialize|unserialize).*(?:req\.|request\.|body|query|params|input|data)`)
	reExtNodeSerializeLib = regexp.MustCompile(`(?i)require\s*\(\s*['"](?:node-serialize|serialize-javascript|serialize-to-js)['"]`)

	// BATOU-DESER-011: Java XMLDecoder with untrusted input
	reExtXMLDecoder      = regexp.MustCompile(`\bnew\s+XMLDecoder\s*\(`)
	reExtXMLDecoderInput = regexp.MustCompile(`\bnew\s+XMLDecoder\s*\(\s*(?:new\s+(?:ByteArrayInputStream|FileInputStream|BufferedInputStream)|request|input|stream|is|body)`)

	// BATOU-DESER-012: Kotlin/JVM serialization of untrusted data
	reExtKotlinDeser     = regexp.MustCompile(`(?i)(?:ObjectInputStream|readObject|Serializable|Externalizable|Kryo|ObjectMapper\.readValue|Gson\.fromJson|Json\.decodeFromString)`)
	reExtKotlinUntrusted = regexp.MustCompile(`(?i)(?:ObjectInputStream|readObject)\s*\(.*(?:request|input|stream|socket|body)`)
)

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func init() {
	rules.Register(&JavaObjectInputStreamRule{})
	rules.Register(&PHPUnserializeRule{})
	rules.Register(&PythonYAMLLoadRule{})
	rules.Register(&DotNetBinaryFormatterRule{})
	rules.Register(&RubyMarshalLoadRule{})
	rules.Register(&NodeSerializeRule{})
	rules.Register(&JavaXMLDecoderRule{})
	rules.Register(&KotlinDeserRule{})
}

// ========================================================================
// BATOU-DESER-005: Java ObjectInputStream.readObject without Filter
// ========================================================================

type JavaObjectInputStreamRule struct{}

func (r *JavaObjectInputStreamRule) ID() string                     { return "BATOU-DESER-005" }
func (r *JavaObjectInputStreamRule) Name() string                   { return "JavaObjectInputStream" }
func (r *JavaObjectInputStreamRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JavaObjectInputStreamRule) Description() string {
	return "Detects Java ObjectInputStream.readObject() usage without an ObjectInputFilter, which enables deserialization RCE."
}
func (r *JavaObjectInputStreamRule) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaObjectInputStreamRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	if reExtObjectFilter.MatchString(ctx.Content) {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m := reExtObjInputStream.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Java ObjectInputStream without deserialization filter",
				Description:   "ObjectInputStream is used without an ObjectInputFilter. Deserializing untrusted data can execute arbitrary code via gadget chains (Apache Commons, Spring, etc.).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Use ObjectInputFilter (Java 9+) to restrict allowed classes. Use ValidatingObjectInputStream from Apache Commons IO. Better yet, use JSON or Protocol Buffers instead of Java serialization.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "java"},
			})
		} else if reExtReadObject.MatchString(line) {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Java readObject() call without deserialization filter",
				Description:   "readObject() deserializes Java objects which can trigger arbitrary code execution if the stream contains malicious gadget chains.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   reExtReadObject.FindString(line),
				Suggestion:    "Add an ObjectInputFilter before calling readObject(). Consider migrating to JSON serialization.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"deserialization", "rce", "java"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-006: PHP unserialize with User Input
// ========================================================================

type PHPUnserializeRule struct{}

func (r *PHPUnserializeRule) ID() string                     { return "BATOU-DESER-006" }
func (r *PHPUnserializeRule) Name() string                   { return "PHPUnserialize" }
func (r *PHPUnserializeRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *PHPUnserializeRule) Description() string {
	return "Detects PHP unserialize() with user-controlled input, which can trigger arbitrary object instantiation and code execution."
}
func (r *PHPUnserializeRule) Languages() []rules.Language {
	return []rules.Language{rules.LangPHP}
}

func (r *PHPUnserializeRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	hasUserSource := reExtPHPUserSource.MatchString(ctx.Content)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m := reExtPHPUnserialize.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "PHP unserialize() with user input (RCE risk)",
				Description:   "unserialize() is called with a variable sourced from user input ($_GET, $_POST, $_REQUEST, etc.). An attacker can craft a serialized payload to instantiate arbitrary objects and achieve remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Never use unserialize() with user input. Use json_decode() instead. If PHP serialization is required, use the allowed_classes option: unserialize($data, ['allowed_classes' => false]).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "php"},
			})
		} else if hasUserSource {
			if m := reExtPHPUnserializeGen.FindString(line); m != "" {
				if hasNearbyPattern(lines, i, reExtPHPUserSource) {
					findings = append(findings, rules.Finding{
						RuleID:        r.ID(),
						Severity:      r.DefaultSeverity(),
						SeverityLabel: r.DefaultSeverity().String(),
						Title:         "PHP unserialize() with potentially untrusted data",
						Description:   "unserialize() is called with a variable that may contain user input. Untrusted deserialization can lead to object injection and code execution.",
						FilePath:      ctx.FilePath,
						LineNumber:    i + 1,
						MatchedText:   m,
						Suggestion:    "Replace unserialize() with json_decode(). If serialization is needed, use allowed_classes: unserialize($data, ['allowed_classes' => ['SafeClass']]).",
						CWEID:         "CWE-502",
						OWASPCategory: "A08:2021-Software and Data Integrity Failures",
						Language:      ctx.Language,
						Confidence:    "medium",
						Tags:          []string{"deserialization", "rce", "php"},
					})
				}
			}
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-007: Python yaml.load without SafeLoader
// ========================================================================

type PythonYAMLLoadRule struct{}

func (r *PythonYAMLLoadRule) ID() string                     { return "BATOU-DESER-007" }
func (r *PythonYAMLLoadRule) Name() string                   { return "PythonYAMLLoad" }
func (r *PythonYAMLLoadRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *PythonYAMLLoadRule) Description() string {
	return "Detects Python yaml.load() without SafeLoader, which can execute arbitrary Python code via YAML tags."
}
func (r *PythonYAMLLoadRule) Languages() []rules.Language {
	return []rules.Language{rules.LangPython}
}

func (r *PythonYAMLLoadRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtYAMLLoad.FindString(line); m != "" {
			// Skip if SafeLoader is used on this line
			if reExtYAMLSafeLoad.MatchString(line) {
				continue
			}
			// Check for Loader=SafeLoader in the call
			if strings.Contains(line, "SafeLoader") || strings.Contains(line, "safe_load") {
				continue
			}
			confidence := "high"
			if reExtYAMLFullLoad.MatchString(line) {
				confidence = "medium" // FullLoader is less dangerous than default
			}
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Python yaml.load() without SafeLoader (RCE risk)",
				Description:   "yaml.load() without Loader=SafeLoader can execute arbitrary Python code via YAML tags like !!python/object/apply:os.system. This is a well-known RCE vector.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader). Never use yaml.load() or yaml.unsafe_load() with untrusted data.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    confidence,
				Tags:          []string{"deserialization", "rce", "yaml", "python"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-008: .NET BinaryFormatter Deserialization
// ========================================================================

type DotNetBinaryFormatterRule struct{}

func (r *DotNetBinaryFormatterRule) ID() string                     { return "BATOU-DESER-008" }
func (r *DotNetBinaryFormatterRule) Name() string                   { return "DotNetBinaryFormatter" }
func (r *DotNetBinaryFormatterRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *DotNetBinaryFormatterRule) Description() string {
	return "Detects .NET BinaryFormatter/LosFormatter/SoapFormatter deserialization, which is inherently insecure."
}
func (r *DotNetBinaryFormatterRule) Languages() []rules.Language {
	return []rules.Language{rules.LangCSharp}
}

func (r *DotNetBinaryFormatterRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		var matched string
		if m := reExtBinaryFormatter.FindString(line); m != "" {
			matched = m
		} else if m := reExtDotNetUnsafe.FindString(line); m != "" {
			matched = m
		}
		if matched != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         ".NET BinaryFormatter deserialization (RCE risk)",
				Description:   "BinaryFormatter and related formatters (LosFormatter, SoapFormatter, NetDataContractSerializer) are inherently insecure. Microsoft explicitly warns against using BinaryFormatter for any purpose.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use System.Text.Json or DataContractSerializer with known types. BinaryFormatter cannot be made safe — it must be replaced entirely.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "csharp", "dotnet"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-009: Ruby Marshal.load with Untrusted Data
// ========================================================================

type RubyMarshalLoadRule struct{}

func (r *RubyMarshalLoadRule) ID() string                     { return "BATOU-DESER-009" }
func (r *RubyMarshalLoadRule) Name() string                   { return "RubyMarshalLoad" }
func (r *RubyMarshalLoadRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *RubyMarshalLoadRule) Description() string {
	return "Detects Ruby Marshal.load/restore with potentially untrusted data, which can execute arbitrary code."
}
func (r *RubyMarshalLoadRule) Languages() []rules.Language {
	return []rules.Language{rules.LangRuby}
}

func (r *RubyMarshalLoadRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reExtRubyMarshalUser.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Ruby Marshal.load with untrusted data (RCE risk)",
				Description:   "Marshal.load/restore deserializes Ruby objects and can instantiate arbitrary classes, including those that execute code in their initialize or finalizer methods.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Use JSON.parse instead of Marshal.load for untrusted data. If Marshal is required, use permitted_classes parameter (Ruby 3.1+): Marshal.load(data, permitted_classes: [SafeClass]).",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "ruby", "marshal"},
			})
		} else if m := reExtRubyMarshalLoad.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Ruby Marshal.load usage (potential RCE risk)",
				Description:   "Marshal.load/restore deserializes arbitrary Ruby objects. If the data source is not trusted, this can lead to remote code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Verify that the data source for Marshal.load is trusted. Prefer JSON for data interchange.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"deserialization", "ruby", "marshal"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-010: Node.js node-serialize/serialize-javascript RCE
// ========================================================================

type NodeSerializeRule struct{}

func (r *NodeSerializeRule) ID() string                     { return "BATOU-DESER-010" }
func (r *NodeSerializeRule) Name() string                   { return "NodeSerialize" }
func (r *NodeSerializeRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *NodeSerializeRule) Description() string {
	return "Detects Node.js node-serialize/serialize-javascript unserialize() usage, which allows arbitrary code execution via function serialization."
}
func (r *NodeSerializeRule) Languages() []rules.Language {
	return []rules.Language{rules.LangJavaScript, rules.LangTypeScript}
}

func (r *NodeSerializeRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	// Check if the file imports node-serialize or similar
	hasLib := reExtNodeSerializeLib.MatchString(ctx.Content)
	if !hasLib {
		return nil
	}
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		var matched string
		if m := reExtNodeSerialize.FindString(line); m != "" {
			matched = m
		} else if m := reExtNodeSerializeReq.FindString(line); m != "" {
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
				Title:         "Node.js unsafe deserialization (RCE via node-serialize)",
				Description:   "The node-serialize library's unserialize() function can execute arbitrary code via serialized JavaScript functions (IIFE payloads). This is a well-known RCE vector (CVE-2017-5941).",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Remove the node-serialize dependency entirely. Use JSON.parse() for data deserialization. Never deserialize untrusted data with libraries that support function serialization.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "node-serialize"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-011: Java XMLDecoder with Untrusted Input
// ========================================================================

type JavaXMLDecoderRule struct{}

func (r *JavaXMLDecoderRule) ID() string                     { return "BATOU-DESER-011" }
func (r *JavaXMLDecoderRule) Name() string                   { return "JavaXMLDecoder" }
func (r *JavaXMLDecoderRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (r *JavaXMLDecoderRule) Description() string {
	return "Detects Java XMLDecoder usage with untrusted input, which can execute arbitrary code from XML."
}
func (r *JavaXMLDecoderRule) Languages() []rules.Language {
	return []rules.Language{rules.LangJava}
}

func (r *JavaXMLDecoderRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m := reExtXMLDecoderInput.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      r.DefaultSeverity(),
				SeverityLabel: r.DefaultSeverity().String(),
				Title:         "Java XMLDecoder with untrusted input (RCE risk)",
				Description:   "XMLDecoder can execute arbitrary Java code from XML input. The XML format supports method calls, field access, and object instantiation, making it equivalent to code execution.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Never use XMLDecoder with untrusted data. Use JAXB, Jackson, or Gson for XML/JSON deserialization instead.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "java", "xmldecoder"},
			})
		} else if m := reExtXMLDecoder.FindString(line); m != "" {
			findings = append(findings, rules.Finding{
				RuleID:        r.ID(),
				Severity:      rules.High,
				SeverityLabel: rules.High.String(),
				Title:         "Java XMLDecoder usage (potential RCE risk)",
				Description:   "XMLDecoder can execute arbitrary Java code from XML. Verify the input source is trusted.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   m,
				Suggestion:    "Replace XMLDecoder with a safe XML deserialization library (JAXB, Jackson). If XMLDecoder is required, ensure input is never user-controlled.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "medium",
				Tags:          []string{"deserialization", "java", "xmldecoder"},
			})
		}
	}
	return findings
}

// ========================================================================
// BATOU-DESER-012: Kotlin/JVM Serialization of Untrusted Data
// ========================================================================

type KotlinDeserRule struct{}

func (r *KotlinDeserRule) ID() string                     { return "BATOU-DESER-012" }
func (r *KotlinDeserRule) Name() string                   { return "KotlinDeserialization" }
func (r *KotlinDeserRule) DefaultSeverity() rules.Severity { return rules.High }
func (r *KotlinDeserRule) Description() string {
	return "Detects Kotlin/JVM deserialization of untrusted data via ObjectInputStream or unfiltered type-based deserialization."
}
func (r *KotlinDeserRule) Languages() []rules.Language {
	return []rules.Language{rules.LangKotlin, rules.LangJava}
}

func (r *KotlinDeserRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	lines := strings.Split(ctx.Content, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if m := reExtKotlinUntrusted.FindString(line); m != "" {
			if reExtObjectFilter.MatchString(ctx.Content) {
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
				Title:         "Kotlin/JVM deserialization of untrusted data",
				Description:   "ObjectInputStream or readObject is used with data from untrusted sources (request, input stream, socket). JVM deserialization can execute arbitrary code via gadget chains.",
				FilePath:      ctx.FilePath,
				LineNumber:    i + 1,
				MatchedText:   matched,
				Suggestion:    "Use kotlinx.serialization with JSON format instead of Java serialization. If Java serialization is required, use ObjectInputFilter to restrict allowed classes.",
				CWEID:         "CWE-502",
				OWASPCategory: "A08:2021-Software and Data Integrity Failures",
				Language:      ctx.Language,
				Confidence:    "high",
				Tags:          []string{"deserialization", "rce", "kotlin", "jvm"},
			})
		}
	}
	return findings
}
