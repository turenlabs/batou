package languages

import (
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
)

func (c *GroovyCatalog) Sanitizers() []taint.SanitizerDef {
	return []taint.SanitizerDef{
		// --- Parameterized SQL ---
		{
			ID:          "groovy.sql.prepared",
			Language:    rules.LangGroovy,
			Pattern:     `PreparedStatement|\.execute\s*\([^"]*,\s*\[`,
			ObjectType:  "groovy.sql.Sql",
			MethodName:  "execute (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Groovy SQL with parameter list (parameterized query)",
		},
		{
			ID:          "groovy.sql.params.list",
			Language:    rules.LangGroovy,
			Pattern:     `\.rows\s*\([^,]+,\s*\[|\.firstRow\s*\([^,]+,\s*\[|\.executeUpdate\s*\([^,]+,\s*\[`,
			ObjectType:  "groovy.sql.Sql",
			MethodName:  "rows/firstRow/executeUpdate (parameterized)",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery},
			Description: "Groovy SQL query methods with parameter list",
		},

		// --- HTML escaping ---
		{
			ID:          "groovy.htmlutils.htmlescape",
			Language:    rules.LangGroovy,
			Pattern:     `HtmlUtils\.htmlEscape\s*\(`,
			ObjectType:  "HtmlUtils",
			MethodName:  "htmlEscape",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Spring HtmlUtils HTML escaping",
		},
		{
			ID:          "groovy.stringescapeutils",
			Language:    rules.LangGroovy,
			Pattern:     `StringEscapeUtils\.escapeHtml\s*\(|StringEscapeUtils\.escapeXml\s*\(`,
			ObjectType:  "StringEscapeUtils",
			MethodName:  "escapeHtml/escapeXml",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Apache Commons StringEscapeUtils HTML/XML escaping",
		},
		{
			ID:          "groovy.encodeashtml",
			Language:    rules.LangGroovy,
			Pattern:     `\.encodeAsHTML\s*\(`,
			ObjectType:  "Grails",
			MethodName:  "encodeAsHTML",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkTemplate},
			Description: "Grails encodeAsHTML codec",
		},
		{
			ID:          "groovy.encodeasurl",
			Language:    rules.LangGroovy,
			Pattern:     `\.encodeAsURL\s*\(`,
			ObjectType:  "Grails",
			MethodName:  "encodeAsURL",
			Neutralizes: []taint.SinkCategory{taint.SnkHTMLOutput, taint.SnkRedirect},
			Description: "Grails encodeAsURL codec",
		},

		// --- Access control annotations ---
		{
			ID:          "groovy.spring.secured",
			Language:    rules.LangGroovy,
			Pattern:     `@Secured`,
			ObjectType:  "Spring",
			MethodName:  "@Secured",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkFileWrite},
			Description: "Spring Security @Secured annotation enforces access control",
		},
		{
			ID:          "groovy.spring.preauthorize",
			Language:    rules.LangGroovy,
			Pattern:     `@PreAuthorize`,
			ObjectType:  "Spring",
			MethodName:  "@PreAuthorize",
			Neutralizes: []taint.SinkCategory{taint.SnkRedirect, taint.SnkFileWrite},
			Description: "Spring Security @PreAuthorize annotation enforces access control",
		},

		// --- Input validation ---
		{
			ID:          "groovy.integer.parseint",
			Language:    rules.LangGroovy,
			Pattern:     `Integer\.parseInt\s*\(|\.toInteger\s*\(|as\s+Integer`,
			ObjectType:  "",
			MethodName:  "parseInt/toInteger",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkFileWrite},
			Description: "Integer conversion restricts to numeric values",
		},
		{
			ID:          "groovy.commandobject",
			Language:    rules.LangGroovy,
			Pattern:     `@Validateable|class\s+\w+Command\b`,
			ObjectType:  "Grails",
			MethodName:  "Command object",
			Neutralizes: []taint.SinkCategory{taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput},
			Description: "Grails command object with validation",
		},

		// --- XXE prevention ---
		{
			ID:          "groovy.xmlslurper.secure",
			Language:    rules.LangGroovy,
			Pattern:     `setFeature\s*\(\s*.*disallow-doctype-decl|XMLConstants\.FEATURE_SECURE_PROCESSING`,
			ObjectType:  "XmlSlurper",
			MethodName:  "setFeature (secure)",
			Neutralizes: []taint.SinkCategory{taint.SnkXPath},
			Description: "XML parser with XXE protection enabled",
		},
	}
}
