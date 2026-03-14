package groovy

import (
	"regexp"
	"strings"

	"github.com/turenlabs/batou/internal/rules"
)

// GVY-017
var (
	reJenkinsFileParam = regexp.MustCompile(`\b(?:readFile|writeFile)\s*\([^)]*\$\{.*(?:params|input|env)`)
)
// GVY-018
var reGrabAnnotationGen = regexp.MustCompile(`@Grab\s*\(`)
// GVY-019
var reJenkinsLoad = regexp.MustCompile(`\bload\s+["'][^"']*\$\{`)
// GVY-020
var reGrailsRenderText = regexp.MustCompile(`\brender\s+text\s*:.*(?:params|request)`)
// GVY-021
var reValueSpEL = regexp.MustCompile(`@Value\s*\(\s*["']\$\{[^}]*#\{`)
// GVY-022
var reJsonSlurperURL = regexp.MustCompile(`(?i)JsonSlurper\s*\(\s*\)\s*\.\s*parse\s*\(.*(?:url|http|URL)`)
// GVY-023
var reHttpRequestSSRF = regexp.MustCompile(`\bhttpRequest\b.*\$\{.*(?:params|env|input)`)
// GVY-024
var reExecuteUpdateInterp = regexp.MustCompile(`\bexecuteUpdate\s*\(\s*["'][^"']*\$\{`)
// GVY-025
var rePipelineInput = regexp.MustCompile(`\binput\s+(?:message|id)\s*:`)
// GVY-026
var (
	reNonCPS = regexp.MustCompile(`@NonCPS`)
	reSecOps = regexp.MustCompile(`(?:new\s+File|FileInputStream|Runtime\.exec|ProcessBuilder|URL\s*\(|HttpURLConnection)`)
)

type JenkinsFileTraversal struct{}
func (r JenkinsFileTraversal) ID() string { return "BATOU-GVY-017" }
func (r JenkinsFileTraversal) Name() string { return "Jenkins File Path Traversal" }
func (r JenkinsFileTraversal) DefaultSeverity() rules.Severity { return rules.Critical }
func (r JenkinsFileTraversal) Description() string { return "Detects Jenkins readFile/writeFile steps with user-controlled paths." }
func (r JenkinsFileTraversal) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r JenkinsFileTraversal) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reJenkinsFileParam.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Jenkins readFile/writeFile with user-controlled path", Description: "readFile or writeFile uses a path containing user parameters. An attacker can use ../ sequences to read or write files outside the workspace.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Validate file paths against an allowlist and verify resolved paths are within the workspace.", CWEID: "CWE-22", OWASPCategory: "A01:2021-Broken Access Control", Language: ctx.Language, Confidence: "high", Tags: []string{"groovy","jenkins","path-traversal"}})
		}
	}
	return findings
}

type GrabDependency struct{}
func (r GrabDependency) ID() string { return "BATOU-GVY-018" }
func (r GrabDependency) Name() string { return "@Grab Dependency Injection" }
func (r GrabDependency) DefaultSeverity() rules.Severity { return rules.High }
func (r GrabDependency) Description() string { return "Detects @Grab annotations pulling dependencies from potentially untrusted repositories." }
func (r GrabDependency) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r GrabDependency) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reGrabAnnotationGen.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "@Grab annotation pulls runtime dependency", Description: "@Grab resolves dependencies at runtime from Maven repositories. Without a trusted @GrabResolver, this can pull malicious packages via dependency confusion.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use @GrabResolver to specify trusted repositories. Pin dependency versions. Prefer build-time dependency management.", CWEID: "CWE-829", OWASPCategory: "A08:2021-Software and Data Integrity Failures", Language: ctx.Language, Confidence: "medium", Tags: []string{"groovy","supply-chain","grab"}})
		}
	}
	return findings
}

type JenkinsLoadInjection struct{}
func (r JenkinsLoadInjection) ID() string { return "BATOU-GVY-019" }
func (r JenkinsLoadInjection) Name() string { return "Jenkins Load Step Injection" }
func (r JenkinsLoadInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r JenkinsLoadInjection) Description() string { return "Detects Jenkins load step with user-controlled script paths." }
func (r JenkinsLoadInjection) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r JenkinsLoadInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reJenkinsLoad.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Jenkins load step with variable script path", Description: "The Jenkins load step loads a Groovy script from a path containing interpolation. An attacker who controls the path can execute arbitrary code.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use static script paths. Validate paths against an allowlist. Consider shared libraries instead.", CWEID: "CWE-94", OWASPCategory: "A03:2021-Injection", Language: ctx.Language, Confidence: "high", Tags: []string{"groovy","jenkins","code-injection"}})
		}
	}
	return findings
}

type GrailsRenderXSS struct{}
func (r GrailsRenderXSS) ID() string { return "BATOU-GVY-020" }
func (r GrailsRenderXSS) Name() string { return "Grails Render Text XSS" }
func (r GrailsRenderXSS) DefaultSeverity() rules.Severity { return rules.High }
func (r GrailsRenderXSS) Description() string { return "Detects Grails render with text parameter containing user input." }
func (r GrailsRenderXSS) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r GrailsRenderXSS) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reGrailsRenderText.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Grails render text with user input", Description: "render text: includes user parameters without HTML encoding, enabling XSS attacks.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use render view: with GSP auto-escaping, or encode output: render text: params.name.encodeAsHTML().", CWEID: "CWE-79", OWASPCategory: "A03:2021-Injection", Language: ctx.Language, Confidence: "high", Tags: []string{"groovy","grails","xss"}})
		}
	}
	return findings
}

type ValueSpELInjection struct{}
func (r ValueSpELInjection) ID() string { return "BATOU-GVY-021" }
func (r ValueSpELInjection) Name() string { return "Spring @Value SpEL Injection" }
func (r ValueSpELInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r ValueSpELInjection) Description() string { return "Detects @Value annotations mixing property placeholders with SpEL expressions." }
func (r ValueSpELInjection) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r ValueSpELInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reValueSpEL.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "@Value annotation with nested SpEL expression", Description: "@Value contains both ${property} and #{SpEL}. If the property value is user-controlled, SpEL can be injected for arbitrary code execution.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Separate property resolution from SpEL evaluation. Validate property values against an allowlist.", CWEID: "CWE-917", OWASPCategory: "A03:2021-Injection", Language: ctx.Language, Confidence: "high", Tags: []string{"groovy","spring","spel-injection"}})
		}
	}
	return findings
}

type JsonSlurperURL struct{}
func (r JsonSlurperURL) ID() string { return "BATOU-GVY-022" }
func (r JsonSlurperURL) Name() string { return "JsonSlurper on Untrusted URL" }
func (r JsonSlurperURL) DefaultSeverity() rules.Severity { return rules.Medium }
func (r JsonSlurperURL) Description() string { return "Detects JsonSlurper.parse() with URL arguments from untrusted sources." }
func (r JsonSlurperURL) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r JsonSlurperURL) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reJsonSlurperURL.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "JsonSlurper parsing data from URL", Description: "JsonSlurper().parse() fetches and parses JSON from a URL. If user-controlled, this enables SSRF.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Validate URLs against an allowlist. Set timeouts and response size limits.", CWEID: "CWE-502", OWASPCategory: "A08:2021-Software and Data Integrity Failures", Language: ctx.Language, Confidence: "medium", Tags: []string{"groovy","json","ssrf"}})
		}
	}
	return findings
}

type JenkinsHttpRequestSSRF struct{}
func (r JenkinsHttpRequestSSRF) ID() string { return "BATOU-GVY-023" }
func (r JenkinsHttpRequestSSRF) Name() string { return "Jenkins httpRequest SSRF" }
func (r JenkinsHttpRequestSSRF) DefaultSeverity() rules.Severity { return rules.High }
func (r JenkinsHttpRequestSSRF) Description() string { return "Detects Jenkins httpRequest step with user-controlled URLs." }
func (r JenkinsHttpRequestSSRF) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r JenkinsHttpRequestSSRF) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reHttpRequestSSRF.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Jenkins httpRequest with user-controlled URL", Description: "httpRequest uses a URL containing user parameters or environment variables, enabling SSRF.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Validate URLs against an allowlist. Never pass user input directly as httpRequest URL.", CWEID: "CWE-918", OWASPCategory: "A10:2021-Server-Side Request Forgery", Language: ctx.Language, Confidence: "high", Tags: []string{"groovy","jenkins","ssrf"}})
		}
	}
	return findings
}

type GORMExecuteUpdateInjection struct{}
func (r GORMExecuteUpdateInjection) ID() string { return "BATOU-GVY-024" }
func (r GORMExecuteUpdateInjection) Name() string { return "GORM executeUpdate Injection" }
func (r GORMExecuteUpdateInjection) DefaultSeverity() rules.Severity { return rules.Critical }
func (r GORMExecuteUpdateInjection) Description() string { return "Detects GORM executeUpdate with GString interpolation enabling HQL injection." }
func (r GORMExecuteUpdateInjection) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r GORMExecuteUpdateInjection) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if reExecuteUpdateInterp.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "GORM executeUpdate with GString interpolation", Description: "executeUpdate uses GString ${} interpolation, concatenating user input into HQL enabling injection.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Use positional parameters: executeUpdate(\"UPDATE User SET name = ? WHERE id = ?\", [name, id]).", CWEID: "CWE-89", OWASPCategory: "A03:2021-Injection", Language: ctx.Language, Confidence: "high", Tags: []string{"groovy","grails","sql-injection","hql"}})
		}
	}
	return findings
}

type PipelineInputNoTimeout struct{}
func (r PipelineInputNoTimeout) ID() string { return "BATOU-GVY-025" }
func (r PipelineInputNoTimeout) Name() string { return "Pipeline Input Without Timeout" }
func (r PipelineInputNoTimeout) DefaultSeverity() rules.Severity { return rules.Medium }
func (r PipelineInputNoTimeout) Description() string { return "Detects Jenkins pipeline input steps without timeout wrapper." }
func (r PipelineInputNoTimeout) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r PipelineInputNoTimeout) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !rePipelineInput.MatchString(ctx.Content) || strings.Contains(ctx.Content, "timeout(") { return nil }
	for i, line := range strings.Split(ctx.Content, "\n") {
		if isComment(line) { continue }
		if rePipelineInput.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "Pipeline input step without timeout", Description: "A pipeline input step waits for manual approval without a timeout wrapper, risking indefinite stalls.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Wrap with timeout: timeout(time: 1, unit: 'HOURS') { input message: '...' }.", CWEID: "CWE-400", OWASPCategory: "A05:2021-Security Misconfiguration", Language: ctx.Language, Confidence: "medium", Tags: []string{"groovy","jenkins","timeout","dos"}})
		}
	}
	return findings
}

type NonCPSSecurityOps struct{}
func (r NonCPSSecurityOps) ID() string { return "BATOU-GVY-026" }
func (r NonCPSSecurityOps) Name() string { return "@NonCPS Security Operations" }
func (r NonCPSSecurityOps) DefaultSeverity() rules.Severity { return rules.High }
func (r NonCPSSecurityOps) Description() string { return "Detects @NonCPS methods performing security-sensitive operations." }
func (r NonCPSSecurityOps) Languages() []rules.Language { return []rules.Language{rules.LangGroovy} }
func (r NonCPSSecurityOps) Scan(ctx *rules.ScanContext) []rules.Finding {
	var findings []rules.Finding
	if !reNonCPS.MatchString(ctx.Content) { return nil }
	lines := strings.Split(ctx.Content, "\n")
	inNonCPS := false
	for i, line := range lines {
		if isComment(line) { continue }
		if reNonCPS.MatchString(line) { inNonCPS = true; continue }
		if inNonCPS && reSecOps.MatchString(line) {
			findings = append(findings, rules.Finding{RuleID: r.ID(), Severity: r.DefaultSeverity(), SeverityLabel: r.DefaultSeverity().String(), Title: "@NonCPS method with security-sensitive operation", Description: "A @NonCPS method performs file I/O, network calls, or process execution, bypassing Jenkins CPS sandbox.", FilePath: ctx.FilePath, LineNumber: i+1, MatchedText: truncate(line, 120), Suggestion: "Move sensitive operations to approved pipeline steps or shared libraries.", CWEID: "CWE-94", OWASPCategory: "A05:2021-Security Misconfiguration", Language: ctx.Language, Confidence: "medium", Tags: []string{"groovy","jenkins","noncps","sandbox"}})
			inNonCPS = false
		}
		if strings.TrimSpace(line) == "}" { inNonCPS = false }
	}
	return findings
}

func init() {
	rules.Register(JenkinsFileTraversal{})
	rules.Register(GrabDependency{})
	rules.Register(JenkinsLoadInjection{})
	rules.Register(GrailsRenderXSS{})
	rules.Register(ValueSpELInjection{})
	rules.Register(JsonSlurperURL{})
	rules.Register(JenkinsHttpRequestSSRF{})
	rules.Register(GORMExecuteUpdateInjection{})
	rules.Register(PipelineInputNoTimeout{})
	rules.Register(NonCPSSecurityOps{})
}
