package taint

import "regexp"

// PropagationRule defines how taint flows through a specific operation type.
type PropagationRule struct {
	Name        string  // e.g., "string_concat", "format_string", "method_chain"
	Pattern     string  // Regex pattern that matches this operation
	Propagates  bool    // Does taint propagate through this operation?
	Confidence  float64 // Confidence multiplier (0.0-1.0)
	Description string  // What this propagation means
}

// DefaultPropagationRules returns the standard propagation rules.
// Order matters: more specific patterns should come before general ones.
func DefaultPropagationRules() []PropagationRule {
	return []PropagationRule{
		// Hashing — data is destroyed, taint does NOT propagate
		{
			Name:        "hash_function",
			Pattern:     `(?i)(hashlib\.\w+|\.hash\(|sha[0-9]+|md5|bcrypt\.hash|crypto\.createHash|digest\(\)|hexdigest\(\))`,
			Propagates:  false,
			Confidence:  0.0,
			Description: "Hashing destroys the original data; taint does not propagate",
		},
		// Encryption — data is transformed, taint does NOT propagate
		{
			Name:        "encryption",
			Pattern:     `(?i)(encrypt|cipher\.|\.seal\(|aes\.|rsa\.|gpg\.|nacl\.)`,
			Propagates:  false,
			Confidence:  0.0,
			Description: "Encryption transforms data; taint does not propagate",
		},
		// Comparison — result is boolean, taint does NOT propagate
		{
			Name:        "comparison",
			Pattern:     `(==|!=|<=|>=|\.equals\(|\.compareTo\(|\.compare\()`,
			Propagates:  false,
			Confidence:  0.0,
			Description: "Comparison produces a boolean; taint does not propagate",
		},
		// String formatting — taint propagates through format operations
		{
			Name:        "format_string",
			Pattern:     `(fmt\.Sprintf|fmt\.Fprintf|\.format\(|f"[^"]*\{|f'[^']*\{|String\.format|sprintf|printf|%[sdvqxf])`,
			Propagates:  true,
			Confidence:  0.95,
			Description: "String formatting preserves tainted data in the output",
		},
		// Template literals (JS/TS)
		{
			Name:        "template_literal",
			Pattern:     "`[^`]*\\$\\{",
			Propagates:  true,
			Confidence:  0.95,
			Description: "Template literal interpolation preserves tainted data",
		},
		// String concatenation — taint propagates
		{
			Name:        "string_concat",
			Pattern:     `(\+\s*["']|["']\s*\+|\.\.\s*["']|["']\s*\.\.|\.concat\()`,
			Propagates:  true,
			Confidence:  0.95,
			Description: "String concatenation preserves tainted data in the result",
		},
		// String methods — taint propagates (data preserved, just transformed)
		{
			Name:        "string_method",
			Pattern:     `(?i)\.(strip|trim|lower|upper|replace|substring|substr|slice|split|chomp|squeeze|downcase|upcase|capitalize|title|lstrip|rstrip|trimStart|trimEnd|trimLeft|trimRight|padStart|padEnd)\(`,
			Propagates:  true,
			Confidence:  0.9,
			Description: "String methods transform but preserve tainted data",
		},
		// Encoding — taint propagates (data is recoverable)
		{
			Name:        "encoding",
			Pattern:     `(?i)(\.encode\(|\.decode\(|base64\.\w+|url\.QueryEscape|encodeURIComponent|encodeURI|urllib\.quote|CGI\.escape|URI\.encode|htmlspecialchars)`,
			Propagates:  true,
			Confidence:  0.9,
			Description: "Encoding transforms data reversibly; taint propagates",
		},
		// Type conversion — taint propagates but with lower confidence
		{
			Name:        "type_conversion",
			Pattern:     `(?i)(str\(|int\(|float\(|bool\(|String\(|Integer\.\w+|Float\.\w+|Number\(|\.toString\(|\.to_s|\.to_i|\.to_f|strconv\.\w+|\.String\(\)|\.Int\(\)|\.Value\(\))`,
			Propagates:  true,
			Confidence:  0.85,
			Description: "Type conversion preserves data semantics; taint propagates",
		},
		// Array/list operations — taint propagates
		{
			Name:        "array_operation",
			Pattern:     `(?i)(\.append\(|\.push\(|\.add\(|\.insert\(|\.extend\(|\.join\(|\.concat\(|strings\.Join|\.unshift\(|\.prepend\()`,
			Propagates:  true,
			Confidence:  0.8,
			Description: "Collection operations may spread taint to the container",
		},
		// Arithmetic — generally does NOT propagate (result is numeric)
		{
			Name:        "arithmetic",
			Pattern:     `[\+\-\*/%]\s*\d|\d\s*[\+\-\*/%]`,
			Propagates:  false,
			Confidence:  0.0,
			Description: "Arithmetic with numeric literals; taint does not propagate",
		},
	}
}

// compiledRule pairs a propagation rule with its compiled regex.
type compiledRule struct {
	rule PropagationRule
	re   *regexp.Regexp
}

// cachedRules holds the compiled propagation rules, initialized once.
var cachedRules []compiledRule

func init() {
	defs := DefaultPropagationRules()
	cachedRules = make([]compiledRule, 0, len(defs))
	for _, r := range defs {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			// Skip rules that fail to compile — this indicates a bug in the pattern.
			continue
		}
		cachedRules = append(cachedRules, compiledRule{rule: r, re: re})
	}
}

// ApplyPropagation checks if taint should propagate through an operation
// and returns the confidence multiplier. It tests the operation string
// against all propagation rules in order and returns the first match.
// If no rule matches, taint propagates with default confidence (1.0).
func ApplyPropagation(operation string) (propagates bool, confidence float64) {
	for _, cr := range cachedRules {
		if cr.re.MatchString(operation) {
			return cr.rule.Propagates, cr.rule.Confidence
		}
	}
	// Default: propagate with full confidence (conservative — assume taint survives).
	return true, 1.0
}

// ApplyPropagationWithMatch is like ApplyPropagation but also reports whether
// a specific propagation rule was matched. When matched is false, the default
// fallthrough (true, 1.0) was used.
func ApplyPropagationWithMatch(operation string) (propagates bool, confidence float64, matched bool) {
	for _, cr := range cachedRules {
		if cr.re.MatchString(operation) {
			return cr.rule.Propagates, cr.rule.Confidence, true
		}
	}
	return true, 1.0, false
}
