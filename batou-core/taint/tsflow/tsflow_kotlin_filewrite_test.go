package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func TestKotlin_FileWrite_Unsafe_FileOutputStream(t *testing.T) {
	code := `
import java.io.FileOutputStream

fun handler() {
    val userPath = readLine()
    val fos = FileOutputStream(userPath)
    fos.write("data".toByteArray())
    fos.close()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> FileOutputStream()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_FileWriter(t *testing.T) {
	code := `
import java.io.FileWriter

fun handler() {
    val userPath = readLine()
    val writer = FileWriter(userPath)
    writer.write("data")
    writer.close()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> FileWriter()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_AppendText(t *testing.T) {
	code := `
import java.io.File

fun handler() {
    val userPath = readLine()
    File(userPath).appendText("appended data")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> File.appendText()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_AppendBytes(t *testing.T) {
	code := `
import java.io.File

fun handler() {
    val userPath = readLine()
    File(userPath).appendBytes("data".toByteArray())
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> File.appendBytes()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_FilesMove(t *testing.T) {
	code := `
import java.nio.file.Files
import java.nio.file.Paths
import java.nio.file.StandardCopyOption

fun handler() {
    val userDest = readLine()
    Files.move(Paths.get("/tmp/upload.bin"), Paths.get(userDest), StandardCopyOption.REPLACE_EXISTING)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> Files.move()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_CreateDirectories(t *testing.T) {
	code := `
import java.nio.file.Files
import java.nio.file.Paths

fun handler() {
    val userDir = readLine()
    Files.createDirectories(Paths.get(userDir))
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> Files.createDirectories()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_CreateSymbolicLink(t *testing.T) {
	code := `
import java.nio.file.Files
import java.nio.file.Paths

fun handler() {
    val userTarget = readLine()
    Files.createSymbolicLink(Paths.get("/data/link"), Paths.get(userTarget))
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> Files.createSymbolicLink()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Unsafe_PathsGet(t *testing.T) {
	code := `
import java.nio.file.Paths

fun handler() {
    val userPath = readLine()
    val path = Paths.get(userPath)
    println(path)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow for readLine -> Paths.get()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_FileWrite_Safe_ToRealPath(t *testing.T) {
	code := `
import java.nio.file.Paths

fun handler() {
    val userPath = readLine()
    val safePath = Paths.get("/base", userPath).toRealPath()
    val content = safePath.toFile().readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when toRealPath() is used")
		}
	}
}

func TestKotlin_FileWrite_Safe_ToAbsolutePath(t *testing.T) {
	code := `
import java.nio.file.Paths

fun handler() {
    val userPath = readLine()
    val absPath = Paths.get("/base", userPath).toAbsolutePath()
    val content = absPath.toFile().readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when toAbsolutePath() is used")
		}
	}
}
