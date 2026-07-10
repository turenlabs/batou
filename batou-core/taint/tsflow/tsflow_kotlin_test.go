package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func TestKotlin_FileRead_Safe_FileName(t *testing.T) {
	code := `
fun handler() {
    val userPath = readLine()
    val safeName = File(userPath).name
    val content = File("/uploads", safeName).readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when File.name extracts filename")
		}
	}
}

func TestKotlin_FileRead_Safe_PathFileName(t *testing.T) {
	code := `
import java.nio.file.Paths
import java.nio.file.Files

fun handler() {
    val userPath = readLine()
    val safeName = Paths.get(userPath).fileName
    val content = Files.readString(Paths.get("/uploads").resolve(safeName))
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when Path.fileName extracts filename")
		}
	}
}

func TestKotlin_FileRead_Safe_Normalize(t *testing.T) {
	code := `
import java.nio.file.Paths

fun handler() {
    val userPath = readLine()
    val normalized = Paths.get("/base", userPath).normalize()
    val content = File(normalized.toString()).readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when Path.normalize() is used")
		}
	}
}

func TestKotlin_FileRead_Safe_CanonicalPath(t *testing.T) {
	code := `
fun handler() {
    val userPath = readLine()
    val canonical = File("/base", userPath).canonicalPath
    val content = File(canonical).readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when canonicalPath is used")
		}
	}
}

func TestKotlin_FileRead_Safe_FilenameUtilsGetName(t *testing.T) {
	code := `
import org.apache.commons.io.FilenameUtils

fun handler() {
    val userPath = readLine()
    val safeName = FilenameUtils.getName(userPath)
    val content = File("/uploads", safeName).readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when FilenameUtils.getName() is used")
		}
	}
}

func TestKotlin_FileRead_Safe_FilenameUtilsNormalize(t *testing.T) {
	code := `
import org.apache.commons.io.FilenameUtils

fun handler() {
    val userPath = readLine()
    val normalized = FilenameUtils.normalize(userPath)
    val content = File(normalized).readText()
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkFileRead && f.Confidence > 0.5 {
			t.Error("expected no high-confidence file read flow when FilenameUtils.normalize() is used")
		}
	}
}

func TestKotlin_FileRead_Unsafe_DirectPath(t *testing.T) {
	// Negative test: user input flows directly to file read without sanitization
	code := `
import java.nio.file.Files
import java.nio.file.Paths

fun handler() {
    val userPath = readLine()
    val content = Files.readString(Paths.get(userPath))
    println(content)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow for readLine -> Files.readString() without sanitization")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}
