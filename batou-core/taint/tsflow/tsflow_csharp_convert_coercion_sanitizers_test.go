package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// C# Convert.ToXxx type-coercion Sanitizer Tests
// =========================================================================
//
// The existing csharp.int.parse entry lists `Convert.ToInt32(` in its regex
// Pattern, but tsflow ignores the Pattern field entirely and matches on
// ObjectType+MethodName (System.Int32 / "int.Parse/TryParse"). A call to
// Convert.ToInt32(raw) has receiver "Convert" and method "ToInt32", which
// never matched the int.Parse entry — so the entire System.Convert numeric
// coercion family was invisible to the structural taint engine. These entries
// (csharp.convert.tointeger / tofloat / toboolean / todatetime) close that gap.
//
// A value coerced to a numeric / boolean / DateTime type cannot carry
// injection metacharacters in any string context, so the coerced result
// neutralises taint before it reaches a downstream sink.
//
// Process.Start is used as the downstream sink (rather than a SqlCommand
// ExecuteQuery variant) to avoid the "Query(" substring trigger that
// auto-taints function parameters in the tsflow webhandler heuristic — the
// same convention used by tsflow_csharp_temporal_parse_sanitizers_test.go.

func assertCSharpConvertCommandSanitized(t *testing.T, code, sanitizerName string) {
	t.Helper()
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Confidence > 0.5 {
			t.Errorf("expected command-injection flow to be sanitized by %s, got confidence %.2f sink=%s",
				sanitizerName, f.Confidence, f.Sink.ID)
		}
	}
}

func TestCSharp_ConvertToInt32_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        int id = Convert.ToInt32(raw);
        Process.Start("/usr/bin/printf", "%s " + id);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToInt32")
}

func TestCSharp_ConvertToInt64_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        long id = Convert.ToInt64(raw);
        Process.Start("/usr/bin/printf", "%s " + id);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToInt64")
}

func TestCSharp_ConvertToByte_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        byte b = Convert.ToByte(raw);
        Process.Start("/usr/bin/printf", "%s " + b);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToByte")
}

func TestCSharp_ConvertToDouble_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        double amount = Convert.ToDouble(raw);
        Process.Start("/usr/bin/printf", "%s " + amount);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToDouble")
}

func TestCSharp_ConvertToDecimal_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        decimal price = Convert.ToDecimal(raw);
        Process.Start("/usr/bin/printf", "%s " + price);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToDecimal")
}

func TestCSharp_ConvertToBoolean_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        bool flag = Convert.ToBoolean(raw);
        Process.Start("/usr/bin/printf", "%s " + flag);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToBoolean")
}

func TestCSharp_ConvertToDateTime_Sanitizes_Command(t *testing.T) {
	code := `
using System;
using System.Diagnostics;

public class Handler {
    public void Run() {
        string raw = Console.ReadLine();
        DateTime when = Convert.ToDateTime(raw);
        Process.Start("/usr/bin/printf", "%s " + when);
    }
}
`
	assertCSharpConvertCommandSanitized(t, code, "Convert.ToDateTime")
}

// Negative control — same shape WITHOUT the Convert coercion must still
// produce a SnkCommand flow at confidence >= 0.5. If this regresses, the
// assertions above stop being meaningful (a silent-pass test would mask
// sanitizer bugs).
func TestCSharp_ConvertCoercionControl_Unsanitized_StillFlows(t *testing.T) {
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

// Registration check — the four new entries must be present in the C# catalog
// with the correct ObjectType, otherwise the structural matcher cannot reach
// them.
func TestCSharp_ConvertCoercionSanitizers_Registered(t *testing.T) {
	want := map[string]bool{
		"csharp.convert.tointeger": false,
		"csharp.convert.tofloat":   false,
		"csharp.convert.toboolean": false,
		"csharp.convert.todatetime": false,
	}
	for _, san := range taint.SanitizersForLanguage(rules.LangCSharp) {
		if _, ok := want[san.ID]; ok {
			want[san.ID] = true
			if san.ObjectType != "System.Convert" {
				t.Errorf("%s: ObjectType = %q, want \"System.Convert\"", san.ID, san.ObjectType)
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("sanitizer %s not registered in C# catalog", id)
		}
	}
}
