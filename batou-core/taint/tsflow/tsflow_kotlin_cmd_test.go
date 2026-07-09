package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Kotlin command injection sinks — Apache Commons Exec, Docker Java,
// Apache MINA SSHD, ZeroTurnaround zt-exec
// =========================================================================

// --- Apache Commons Exec ---

func TestKotlin_CommonsExec_CommandLineParse_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val userInput = readLine()
    val cmdLine = CommandLine.parse(userInput)
    val executor = DefaultExecutor()
    executor.execute(cmdLine)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> CommandLine.parse()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_CommonsExec_DefaultExecutor_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    val cmdLine = CommandLine.parse(cmd)
    val executor = DefaultExecutor()
    executor.execute(cmdLine)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> DefaultExecutor.execute()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_CommonsExec_AddArgument_Safe(t *testing.T) {
	code := `
fun handler() {
    val userArg = readLine()
    val cmdLine = CommandLine("ls")
    cmdLine.addArgument(userArg)
    val executor = DefaultExecutor()
    executor.execute(cmdLine)
}
`
	flows := Analyze(code, "/app/Service.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.7 {
			t.Error("expected CommandLine.addArgument to sanitize command injection flow")
		}
	}
}

// --- Docker Java ---

func TestKotlin_DockerJava_ExecCreateCmd_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    dockerClient.execCreateCmd(cmd)
}
`
	flows := Analyze(code, "/app/DockerService.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> dockerClient.execCreateCmd()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Apache MINA SSHD ---

func TestKotlin_ApacheSSHD_ExecuteRemoteCommand_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    session.executeRemoteCommand(cmd)
}
`
	flows := Analyze(code, "/app/SshService.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> session.executeRemoteCommand()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- ZeroTurnaround zt-exec ---

func TestKotlin_ZtExec_ProcessExecutor_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    val processExecutor = ProcessExecutor()
    processExecutor.command(cmd)
}
`
	flows := Analyze(code, "/app/ExecService.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> ProcessExecutor().command()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Existing sinks: verify baseline still works ---

func TestKotlin_RuntimeExec_Cmd_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    Runtime.getRuntime().exec(cmd)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> Runtime.getRuntime().exec()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_ProcessBuilder_Cmd_Vulnerable(t *testing.T) {
	code := `
fun handler() {
    val cmd = readLine()
    val pb = ProcessBuilder(cmd)
    pb.start()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow for readLine -> ProcessBuilder()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
