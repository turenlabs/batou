package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Python Streamlit input-widget sources. Streamlit is the dominant
// Python framework for AI/LLM app prototyping (LangChain UIs, RAG apps,
// Hugging Face Spaces, internal admin tools), and user input from its
// widgets routinely flows directly into subprocess, eval/exec, SQL queries,
// and LLM prompt-template formatters without sanitization.
//
// The canonical import is `import streamlit as st`, so the matcher's
// prefix-abbreviation heuristic (lastPart "streamlit" → HasPrefix("streamlit",
// "st")) ties the receiver "st" to ObjectType "streamlit". Widget MethodNames
// (text_input, chat_input, file_uploader, etc.) are Streamlit-specific so
// there is no cross-library collision risk.
//
// Tests wrap call sites in a `def handler():` block — tsflow's Python walker
// only traverses inside function definitions. Real Streamlit apps put their
// logic at module top-level, but the catalog matching is identical either
// way; we wrap for the test harness to actually walk the statements.

func TestPython_Streamlit_SourcesRegistered(t *testing.T) {
	sources := taint.SourcesForLanguage(rules.LangPython)
	want := []string{
		"py.streamlit.text_input",
		"py.streamlit.text_area",
		"py.streamlit.chat_input",
		"py.streamlit.file_uploader",
		"py.streamlit.camera_input",
		"py.streamlit.audio_input",
		"py.streamlit.data_editor",
		"py.streamlit.query_params",
		"py.streamlit.experimental_get_query_params",
	}
	for _, id := range want {
		found := false
		for _, s := range sources {
			if s.ID == id {
				found = true
				if s.Category != taint.SrcUserInput {
					t.Errorf("source %s: expected SrcUserInput, got %v", id, s.Category)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected source %s to be registered for Python", id)
		}
	}
}

// --- st.text_input -> command injection sink ---
// Common LLM-app pattern: user enters a "filename" or "topic" in a Streamlit
// text input, and the backend pipes it into a shell command for processing.

func TestPython_Streamlit_TextInput_CommandInjection(t *testing.T) {
	code := `
import streamlit as st
import subprocess

def handler():
    prompt = st.text_input("Filename")
    subprocess.call("cat " + prompt, shell=True)
`
	flows := Analyze(code, "/app/streamlit_app.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from st.text_input -> subprocess.call")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.text_area -> SQL sink ---

func TestPython_Streamlit_TextArea_SQLi(t *testing.T) {
	code := `
import streamlit as st
import sqlite3

def save_note(cursor):
    note = st.text_area("Notes")
    query = "INSERT INTO notes (body) VALUES ('" + note + "')"
    cursor.execute(query)
`
	flows := Analyze(code, "/app/streamlit_app.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from st.text_area -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.chat_input -> command injection sink (LLM agent pattern) ---
// st.chat_input is the canonical LLM chat-interface widget. Many LangChain /
// CrewAI / ReAct-agent demos let the model decide to spawn shell commands
// based on the user's chat message. This is the highest-impact source we
// are adding in this cycle.

func TestPython_Streamlit_ChatInput_CommandInjection(t *testing.T) {
	code := `
import streamlit as st
import subprocess

def chat():
    user_msg = st.chat_input("Ask anything")
    subprocess.run("echo " + user_msg, shell=True)
`
	flows := Analyze(code, "/app/chat.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from st.chat_input -> subprocess.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.chat_input -> code execution sink (eval) ---
// Common in "AI calculator" or "code interpreter" Streamlit demos.

func TestPython_Streamlit_ChatInput_CodeExec(t *testing.T) {
	code := `
import streamlit as st

def calc():
    prompt = st.chat_input("Expression")
    result = eval(prompt)
    return result
`
	flows := Analyze(code, "/app/calc.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-execution flow from st.chat_input -> eval")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.file_uploader -> command injection ---
// UploadedFile.name is attacker-controlled; passing it to a subprocess for
// e.g. `pdftotext` conversion is a classic path-based command injection.

func TestPython_Streamlit_FileUploader_CommandInjection(t *testing.T) {
	code := `
import streamlit as st
import os

def upload():
    uploaded = st.file_uploader("Upload a PDF")
    os.system("pdftotext " + uploaded)
`
	flows := Analyze(code, "/app/upload.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from st.file_uploader -> os.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.camera_input -> command injection ---
// Camera input returns image bytes that are typically saved to disk; the
// filename or path constructed from the upload is what reaches the sink.

func TestPython_Streamlit_CameraInput_CommandInjection(t *testing.T) {
	code := `
import streamlit as st
import subprocess

def take_photo():
    img = st.camera_input("Take a photo")
    subprocess.call("convert " + img + " out.png", shell=True)
`
	flows := Analyze(code, "/app/camera.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from st.camera_input -> subprocess.call")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.audio_input -> command injection ---
// Audio recording widget (Streamlit 1.31+). Common pattern: pipe into ffmpeg
// or whisper CLI.

func TestPython_Streamlit_AudioInput_CommandInjection(t *testing.T) {
	code := `
import streamlit as st
import os

def transcribe():
    clip = st.audio_input("Record")
    os.system("ffmpeg -i " + clip + " out.mp3")
`
	flows := Analyze(code, "/app/audio.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from st.audio_input -> os.system")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.data_editor -> SQL sink ---
// st.data_editor lets the user edit a dataframe in-place. Apps that persist
// edits to a database often build raw INSERT/UPDATE strings from the
// returned dataframe rows.

func TestPython_Streamlit_DataEditor_SQLi(t *testing.T) {
	code := `
import streamlit as st

def save(cursor, initial_df):
    edited = st.data_editor(initial_df)
    query = "UPDATE rows SET name = '" + edited + "' WHERE id = 1"
    cursor.execute(query)
`
	flows := Analyze(code, "/app/edit.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from st.data_editor -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.query_params -> SQL sink ---
// URL query params are attacker-controllable via crafted links; flowing
// them into raw SQL is a CWE-89 case.

func TestPython_Streamlit_QueryParams_SQLi(t *testing.T) {
	code := `
import streamlit as st

def lookup(cursor):
    raw = st.query_params
    q = "SELECT * FROM users WHERE name = '" + raw + "'"
    cursor.execute(q)
`
	flows := Analyze(code, "/app/dash.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from st.query_params -> cursor.execute")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- st.experimental_get_query_params (deprecated) -> command injection ---

func TestPython_Streamlit_ExperimentalQueryParams_CommandInjection(t *testing.T) {
	code := `
import streamlit as st
import subprocess

def legacy():
    params = st.experimental_get_query_params()
    subprocess.call("echo " + params, shell=True)
`
	flows := Analyze(code, "/app/legacy.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from st.experimental_get_query_params -> subprocess.call")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Negative: hardcoded value passed to subprocess should NOT taint ---
// Regression guard against the catalog accidentally over-matching `st.X(...)`
// for non-input methods (e.g. st.write, st.title) — those are not in the
// catalog and constant strings should never produce a flow.

func TestPython_Streamlit_HardcodedValue_NoFlow(t *testing.T) {
	code := `
import streamlit as st
import subprocess

def safe():
    st.title("Static title")
    name = "static-value"
    subprocess.call("echo " + name, shell=True)
`
	flows := Analyze(code, "/app/static.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected NO flow for hardcoded string passed to subprocess.call")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s", f.Source.Category, f.Sink.Category)
		}
	}
}
