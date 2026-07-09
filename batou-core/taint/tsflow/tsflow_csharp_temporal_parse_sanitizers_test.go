package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# Temporal-Parse Sanitizer Tests
// =========================================================================
//
// Verifies the value returned by DateTime.ParseExact / DateTimeOffset.Parse /
// DateOnly.Parse / TimeOnly.Parse / TimeSpan.Parse (and their TryParse /
// ParseExact / TryParseExact siblings) neutralises taint before reaching
// downstream sinks. These complement the existing csharp.datetime.parse
// entry (which covers DateTime.Parse / DateTime.TryParse only).
//
// Each parsed value is a strongly-typed struct (DateTime / DateTimeOffset /
// DateOnly / TimeOnly / TimeSpan) whose ToString() produces a bounded
// numeric/ISO format with no characters dangerous to SQL, shell, log, file
// path, HTML, or redirect contexts.
//
// Process.Start is used as the downstream sink rather than any
// SqlCommand.ExecuteQuery variant to avoid the "Query(" substring trigger
// that auto-taints function parameters in the tsflow webhandler heuristic.

func assertCSharpTemporalCommandSanitized(t *testing.T, code, sanitizerName string) {
	t.Helper()
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("expected command-injection flow to be sanitized by %s, got confidence %.2f sink=%s",
				sanitizerName, f.Confidence, f.Sink.ID)
		}
	}
}

func TestCSharp_DateTimeParseExact_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Globalization;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateTime when = DateTime.ParseExact(raw, "yyyy-MM-dd", CultureInfo.InvariantCulture);
        Process.Start("/usr/bin/printf", "%s " + when);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateTime.ParseExact")
}

func TestCSharp_DateTimeTryParseExact_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Globalization;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateTime when;
        DateTime.TryParseExact(raw, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out when);
        Process.Start("/usr/bin/printf", "%s " + when);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateTime.TryParseExact")
}

func TestCSharp_DateTimeOffsetParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateTimeOffset moment = DateTimeOffset.Parse(raw);
        Process.Start("/usr/bin/printf", "%s " + moment);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateTimeOffset.Parse")
}

func TestCSharp_DateTimeOffsetTryParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateTimeOffset moment;
        DateTimeOffset.TryParse(raw, out moment);
        Process.Start("/usr/bin/printf", "%s " + moment);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateTimeOffset.TryParse")
}

func TestCSharp_DateTimeOffsetParseExact_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Globalization;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateTimeOffset moment = DateTimeOffset.ParseExact(raw, "yyyy-MM-ddTHH:mm:sszzz", CultureInfo.InvariantCulture);
        Process.Start("/usr/bin/printf", "%s " + moment);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateTimeOffset.ParseExact")
}

func TestCSharp_DateOnlyParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateOnly day = DateOnly.Parse(raw);
        Process.Start("/usr/bin/printf", "%s " + day);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateOnly.Parse")
}

func TestCSharp_DateOnlyTryParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateOnly day;
        DateOnly.TryParse(raw, out day);
        Process.Start("/usr/bin/printf", "%s " + day);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateOnly.TryParse")
}

func TestCSharp_DateOnlyParseExact_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Globalization;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateOnly day = DateOnly.ParseExact(raw, "yyyy-MM-dd", CultureInfo.InvariantCulture);
        Process.Start("/usr/bin/printf", "%s " + day);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "DateOnly.ParseExact")
}

func TestCSharp_TimeOnlyParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        TimeOnly t = TimeOnly.Parse(raw);
        Process.Start("/usr/bin/printf", "%s " + t);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "TimeOnly.Parse")
}

func TestCSharp_TimeOnlyTryParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        TimeOnly t;
        TimeOnly.TryParse(raw, out t);
        Process.Start("/usr/bin/printf", "%s " + t);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "TimeOnly.TryParse")
}

func TestCSharp_TimeOnlyParseExact_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Globalization;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        TimeOnly t = TimeOnly.ParseExact(raw, "HH:mm:ss", CultureInfo.InvariantCulture);
        Process.Start("/usr/bin/printf", "%s " + t);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "TimeOnly.ParseExact")
}

func TestCSharp_TimeSpanParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        TimeSpan d = TimeSpan.Parse(raw);
        Process.Start("/usr/bin/printf", "%s " + d);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "TimeSpan.Parse")
}

func TestCSharp_TimeSpanTryParse_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        TimeSpan d;
        TimeSpan.TryParse(raw, out d);
        Process.Start("/usr/bin/printf", "%s " + d);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "TimeSpan.TryParse")
}

func TestCSharp_TimeSpanParseExact_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;
using System.Globalization;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        TimeSpan d = TimeSpan.ParseExact(raw, "g", CultureInfo.InvariantCulture);
        Process.Start("/usr/bin/printf", "%s " + d);
    }
}
`
	assertCSharpTemporalCommandSanitized(t, code, "TimeSpan.ParseExact")
}

// Negative control — same shape WITHOUT the parse sanitizer must still produce
// a SnkCommand flow at confidence >= 0.5. If this regresses, the assertions
// above stop being meaningful (a silent-pass test would mask sanitizer bugs).
func TestCSharp_TemporalParseControl_Unsanitized_StillFlows(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        Process.Start("/usr/bin/printf", "%s " + raw);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence >= 0.5 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("negative control: expected SnkCommand flow with confidence >= 0.5 on unsanitized input — sanitizer tests above stop being meaningful without this baseline")
	}
}
