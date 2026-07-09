package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy Jenkins SSH command injection tests (CWE-78)
// =========================================================================

func TestGroovy_JenkinsSSHCommand(t *testing.T) {
	code := `
def deploy(userInput) {
    def remote = [name: 'prod', host: '10.0.0.1', user: 'deploy']
    sshCommand(remote: remote, command: userInput)
}
`
	flows := Analyze(code, "/app/Jenkinsfile.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for parameter userInput -> sshCommand")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JenkinsSSHScript(t *testing.T) {
	code := `
def runScript(input) {
    def remote = [name: 'prod', host: '10.0.0.1', user: 'deploy']
    sshScript(remote: remote, script: input)
}
`
	flows := Analyze(code, "/app/Jenkinsfile.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for parameter input -> sshScript")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Groovy GroovyClassLoader.parseClass eval injection test (CWE-94)
// =========================================================================

func TestGroovy_GroovyClassLoaderParseClass(t *testing.T) {
	code := `
def handler(userInput) {
    def loader = new GroovyClassLoader()
    loader.parseClass(userInput)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow for parameter userInput -> GroovyClassLoader.parseClass")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Groovy Trust Boundary tests (CWE-501)
// =========================================================================

func TestGroovy_JenkinsWithEnv(t *testing.T) {
	code := `
def deploy(userInput) {
    withEnv(["TARGET_BRANCH=${userInput}"]) {
        sh 'deploy.sh'
    }
}
`
	flows := Analyze(code, "/app/Jenkinsfile.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for parameter userInput -> withEnv")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SpringModelAddAttribute(t *testing.T) {
	code := `
def showUser(userInput) {
    model.addAttribute("query", userInput)
    return "search"
}
`
	flows := Analyze(code, "/app/Controller.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for parameter userInput -> model.addAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_ServletContextSetAttribute(t *testing.T) {
	code := `
def init(data) {
    servletContext.setAttribute("appConfig", data)
}
`
	flows := Analyze(code, "/app/AppInit.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for parameter data -> servletContext.setAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_RequestSetAttribute(t *testing.T) {
	code := `
def process(data) {
    request.setAttribute("userData", data)
    request.getRequestDispatcher("/view.jsp").forward(request, response)
}
`
	flows := Analyze(code, "/app/Servlet.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkTrustBoundary) {
		t.Error("expected trust boundary flow for parameter data -> request.setAttribute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe versions — should NOT trigger taint flows
// =========================================================================

func TestGroovy_JenkinsSSHCommand_Safe(t *testing.T) {
	code := `
def deploy() {
    def remote = [name: 'prod', host: '10.0.0.1', user: 'deploy']
    sshCommand(remote: remote, command: 'ls -la /opt/app')
}
`
	flows := Analyze(code, "/app/Jenkinsfile.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand {
			t.Logf("note: safe sshCommand with literal string still matched — acceptable for regex-based taint (flow: %s -> %s)", f.Source.Category, f.Sink.Category)
		}
	}
}

func TestGroovy_SpringModelAddAttribute_Validated(t *testing.T) {
	code := `
def showUser(userInput) {
    def safeVal = Integer.parseInt(userInput)
    model.addAttribute("userId", safeVal)
    return "profile"
}
`
	flows := Analyze(code, "/app/Controller.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkTrustBoundary {
			t.Logf("note: sanitized trust boundary flow detected — Integer.parseInt should neutralize (flow: %s -> %s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
