package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Ruby OS-command injection via an interpolated/concatenated string reaching a
// shell-exec sink (CWE-78).
//
// Verified recall gap (railsgoat app/models/benefits.rb:15 —
// `system("cp #{full_file_name} #{data_path}/bak#{Time.zone.now.to_i}_#{file
// .original_filename}")`): the planted command injection produced ZERO
// dataflow-confirmed CWE-78 because of THREE compounding defects, all fixed by
// this change:
//
//  1. The `.original_filename` upload source was dead in the dataflow engine.
//     The `ruby.rails.upload` catalog entry keyed under MethodName "UploadedFile",
//     so the structural tsflow matcher (which keys sources on the CALLED method
//     name) never seeded `file.original_filename`. A companion source keyed under
//     `original_filename` fixes the seeding.
//  2. The inline-sanitizer check (containsInlineSanitizer) was over-broad on
//     interpolated strings: a `.to_i` on a SIBLING `#{Time.now.to_i}` segment
//     wrongly suppressed a tainted `#{file.original_filename}` in a DIFFERENT
//     segment. The segment-aware inlineSanitizerNeutralizesTaint /
//     inlineSourceSanitizedInSegment require the sanitizer to wrap the tainted
//     segment.
//  3. Ruby backtick (`` `cmd` ``) and `%x{cmd}` parse as a `subshell` node, not a
//     `call`, so they never reached the call-sink path — the ruby.backticks /
//     ruby.percent_x sinks were dead in the dataflow engine. processRubySubshellSink
//     handles them.
//
// The precision boundary (mirrors the parameterized-vs-interpolated SQL
// distinction): the array / multi-arg form `system("ls", dir)` runs WITHOUT a
// shell and must NOT fire; `Shellwords.escape`/`split`/`join` sanitize; the
// tainted interpolation reaching the single-string form is the only dangerous
// shape.

func rbCmdiFlow(t *testing.T, code string) bool {
	t.Helper()
	return hasTaintFlow(Analyze(code, "/app/models/x.rb", rules.LangRuby), taint.SnkCommand)
}

// TestRubyCmdi_InterpolatedShellExec_Fires is the load-bearing positive set.
// Reverting any of the three fixes drops at least one of these to 0 flows.
func TestRubyCmdi_InterpolatedShellExec_Fires(t *testing.T) {
	cases := map[string]string{
		// system("...#{tainted}...") — the dominant shape.
		"system_interp_var": "def m\n  fn = params[:f]\n  system(\"cp #{fn} /tmp/dest\")\nend",
		// system with a chained-call sibling interpolation (#{Time.now.to_i}) —
		// regression guard for the over-broad sanitizer-lift bug.
		"system_chain_sibling": "def m\n  fn = params[:f]\n  system(\"cp #{fn} #{Time.now.to_i}\")\nend",
		// .original_filename upload source, interpolated directly into the sink.
		"system_original_filename": "def m(file)\n  system(\"cp #{file.original_filename} /tmp/x\")\nend",
		// .original_filename via an intermediate variable.
		"system_original_filename_var": "def m(file)\n  name = file.original_filename\n  system(\"cp #{name} /tmp/x\")\nend",
		// The exact railsgoat benefits.rb:15 shape (class + singleton + block +
		// chained sibling + .original_filename as the LAST interpolation).
		"railsgoat_exact": "class Benefits < ApplicationRecord\n" +
			"  def self.make_backup(file, data_path, full_file_name)\n" +
			"    silence_streams(STDERR) { system(\"cp #{full_file_name} #{data_path}/bak#{Time.zone.now.to_i}_#{file.original_filename}\") }\n" +
			"  end\nend",
		// exec("...#{tainted}...")
		"exec_interp": "def m\n  c = params[:c]\n  exec(\"run #{c}\")\nend",
		// Backtick subshell with interpolated taint.
		"backtick_interp": "def m\n  fn = params[:f]\n  out = `cat #{fn}`\nend",
		// Backtick with inline source (no intermediate variable).
		"backtick_inline_source": "def m\n  out = `cat #{params[:f]}`\nend",
		// %x{...#{tainted}...}
		"percent_x_interp": "def m\n  fn = params[:f]\n  out = %x{cat #{fn}}\nend",
		// Concatenation form reaching system.
		"system_concat": "def m\n  fn = params[:f]\n  system(\"cp \" + fn + \" /tmp\")\nend",
		// IO.popen string form with interpolation.
		"io_popen_interp": "def m\n  fn = params[:f]\n  IO.popen(\"tail #{fn}\")\nend",
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			if !rbCmdiFlow(t, code) {
				t.Fatalf("expected CWE-78 command-injection flow, got none:\n%s", code)
			}
		})
	}
}

// TestRubyCmdi_SafeForms_DoNotFire is the load-bearing negative set: the
// shell-free and sanitized shapes must stay clean. These are the FP traps that a
// blunter fix would light up.
func TestRubyCmdi_SafeForms_DoNotFire(t *testing.T) {
	cases := map[string]string{
		// Array / multi-arg form: Ruby runs this WITHOUT a shell, so an
		// interpolation-free tainted arg is safe.
		"system_array_multiarg": "def m\n  dir = params[:dir]\n  system(\"ls\", dir)\nend",
		// Open3 array form (no shell).
		"open3_array": "def m\n  dir = params[:dir]\n  Open3.capture2(\"ls\", dir)\nend",
		// Shellwords.escape sanitizes the tainted value.
		"shellwords_escape": "def m\n  n = params[:n]\n  system(\"cp #{Shellwords.escape(n)} /tmp\")\nend",
		// .to_i coercion on the TAINTED value itself (the sanitizer wraps the
		// tainted segment) — must stay suppressed.
		"to_i_on_tainted": "def m\n  id = params[:id]\n  system(\"echo #{id.to_i}\")\nend",
		// Inline source coerced in the same segment.
		"to_i_inline_source": "def m\n  system(\"echo #{params[:id].to_i}\")\nend",
		// Backtick with the tainted value coerced.
		"backtick_to_i": "def m\n  id = params[:id]\n  out = `echo #{id.to_i}`\nend",
		// Backtick Shellwords-escaped.
		"backtick_shellwords": "def m\n  n = params[:n]\n  out = `cat #{Shellwords.escape(n)}`\nend",
		// Pure-literal command, no taint.
		"pure_literal": "def m\n  system(\"ls -la /tmp\")\nend",
		// Pure-literal backtick.
		"pure_literal_backtick": "def m\n  out = `ls -la`\nend",
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			if rbCmdiFlow(t, code) {
				t.Fatalf("expected NO command-injection flow (safe form), but one fired:\n%s", code)
			}
		})
	}
}
