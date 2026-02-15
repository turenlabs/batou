package languages

import (
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
)

func (c *GroovyCatalog) Sources() []taint.SourceDef {
	return []taint.SourceDef{
		// --- Grails framework ---
		{
			ID:          "groovy.grails.params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `params\.\w+|params\[`,
			ObjectType:  "GrailsController",
			MethodName:  "params",
			Description: "Grails request parameters",
			Assigns:     "return",
		},
		{
			ID:          "groovy.grails.request.getparameter",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `request\.getParameter\s*\(`,
			ObjectType:  "HttpServletRequest",
			MethodName:  "getParameter",
			Description: "Servlet request parameter in Grails",
			Assigns:     "return",
		},
		{
			ID:          "groovy.grails.request.json",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `request\.JSON`,
			ObjectType:  "GrailsRequest",
			MethodName:  "JSON",
			Description: "Grails JSON request body",
			Assigns:     "return",
		},
		{
			ID:          "groovy.grails.session",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `session\.\w+|session\[`,
			ObjectType:  "GrailsController",
			MethodName:  "session",
			Description: "Grails session data",
			Assigns:     "return",
		},
		{
			ID:          "groovy.grails.cookies",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `cookies\.\w+|request\.getCookies\s*\(`,
			ObjectType:  "GrailsController",
			MethodName:  "cookies",
			Description: "Grails cookie values",
			Assigns:     "return",
		},

		// --- Jenkins pipeline ---
		{
			ID:          "groovy.jenkins.env",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangGroovy,
			Pattern:     `env\.\w+`,
			ObjectType:  "JenkinsPipeline",
			MethodName:  "env",
			Description: "Jenkins environment variable",
			Assigns:     "return",
		},
		{
			ID:          "groovy.jenkins.params",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `params\.\w+`,
			ObjectType:  "JenkinsPipeline",
			MethodName:  "params",
			Description: "Jenkins build parameters",
			Assigns:     "return",
		},
		{
			ID:          "groovy.jenkins.currentbuild",
			Category:    taint.SrcExternal,
			Language:    rules.LangGroovy,
			Pattern:     `currentBuild\.\w+`,
			ObjectType:  "JenkinsPipeline",
			MethodName:  "currentBuild",
			Description: "Jenkins current build properties",
			Assigns:     "return",
		},
		{
			ID:          "groovy.jenkins.input",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `input\s*\(|input\s+message`,
			ObjectType:  "JenkinsPipeline",
			MethodName:  "input",
			Description: "Jenkins user input step",
			Assigns:     "return",
		},

		// --- System / Environment ---
		{
			ID:          "groovy.system.getenv",
			Category:    taint.SrcEnvVar,
			Language:    rules.LangGroovy,
			Pattern:     `System\.getenv\s*\(`,
			ObjectType:  "System",
			MethodName:  "getenv",
			Description: "System environment variable",
			Assigns:     "return",
		},
		{
			ID:          "groovy.args",
			Category:    taint.SrcCLIArg,
			Language:    rules.LangGroovy,
			Pattern:     `\bargs\b`,
			ObjectType:  "",
			MethodName:  "args",
			Description: "Command-line arguments",
			Assigns:     "return",
		},

		// --- IO / Network ---
		{
			ID:          "groovy.inputstream",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGroovy,
			Pattern:     `\.inputStream|InputStream|\.newInputStream\s*\(`,
			ObjectType:  "",
			MethodName:  "InputStream",
			Description: "Input stream data",
			Assigns:     "return",
		},
		{
			ID:          "groovy.jsonslurper",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangGroovy,
			Pattern:     `new\s+JsonSlurper\s*\(\s*\)\s*\.parse`,
			ObjectType:  "JsonSlurper",
			MethodName:  "parse/parseText",
			Description: "JSON parsing via JsonSlurper",
			Assigns:     "return",
		},
		{
			ID:          "groovy.url.text",
			Category:    taint.SrcNetwork,
			Language:    rules.LangGroovy,
			Pattern:     `new\s+URL\s*\(.*\)\.text|\.toURL\s*\(\s*\)\s*\.text`,
			ObjectType:  "URL",
			MethodName:  "text",
			Description: "URL content fetched as text",
			Assigns:     "return",
		},

		// --- File reads ---
		{
			ID:          "groovy.file.text",
			Category:    taint.SrcFileRead,
			Language:    rules.LangGroovy,
			Pattern:     `new\s+File\s*\(.*\)\.text|\.eachLine\s*\{`,
			ObjectType:  "File",
			MethodName:  "text/eachLine",
			Description: "File content read in Groovy",
			Assigns:     "return",
		},

		// --- Database ---
		{
			ID:          "groovy.sql.rows",
			Category:    taint.SrcDatabase,
			Language:    rules.LangGroovy,
			Pattern:     `\.rows\s*\(|\.firstRow\s*\(|\.eachRow\s*\(`,
			ObjectType:  "groovy.sql.Sql",
			MethodName:  "rows/firstRow/eachRow",
			Description: "Groovy SQL query results",
			Assigns:     "return",
		},

		// --- HttpServletRequest headers ---
		{
			ID:          "groovy.servlet.getheader",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `request\.getHeader\s*\(|request\.headers`,
			ObjectType:  "HttpServletRequest",
			MethodName:  "getHeader",
			Description: "Servlet request header",
			Assigns:     "return",
		},
		{
			ID:          "groovy.grails.request.forwarduri",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `request\.forwardURI|request\.requestURI`,
			ObjectType:  "HttpServletRequest",
			MethodName:  "requestURI",
			Description: "Request URI (potentially tainted)",
			Assigns:     "return",
		},

		// --- Micronaut ---
		{
			ID:          "groovy.micronaut.parameter",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `@QueryValue|@PathVariable|@Body|@Header|@CookieValue`,
			ObjectType:  "Micronaut",
			MethodName:  "@QueryValue/@PathVariable/@Body",
			Description: "Micronaut request parameter binding",
			Assigns:     "return",
		},

		// --- Ratpack ---
		{
			ID:          "groovy.ratpack.context",
			Category:    taint.SrcUserInput,
			Language:    rules.LangGroovy,
			Pattern:     `ctx\.request|ctx\.getRequest\s*\(\s*\)|context\.request`,
			ObjectType:  "Ratpack",
			MethodName:  "ctx.request",
			Description: "Ratpack request context",
			Assigns:     "return",
		},

		// --- YAML parsing ---
		{
			ID:          "groovy.yaml.parse",
			Category:    taint.SrcDeserialized,
			Language:    rules.LangGroovy,
			Pattern:     `new\s+YamlSlurper\s*\(\s*\)\s*\.parse|Yaml\(\)\.load\s*\(`,
			ObjectType:  "YamlSlurper",
			MethodName:  "parse",
			Description: "YAML parsed data from untrusted source",
			Assigns:     "return",
		},

		// --- XML parsing ---
		{
			ID:          "groovy.xmlslurper.source",
			Category:    taint.SrcExternal,
			Language:    rules.LangGroovy,
			Pattern:     `new\s+XmlSlurper\s*\(\s*\)\s*\.parse\s*\(|XmlSlurper\s*\(\s*\)\s*\.parseText\s*\(`,
			ObjectType:  "XmlSlurper",
			MethodName:  "parse/parseText",
			Description: "XML parsed data from external source",
			Assigns:     "return",
		},
	}
}
