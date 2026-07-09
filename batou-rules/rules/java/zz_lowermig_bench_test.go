package java

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Java-rule-heavy ScanContext: a spread of lines the Java
// rules scan, most of which carry no trigger (the realistic majority case where
// the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line path.
func lowermigCtx(base []string) *rules.ScanContext {
	var lines []string
	for len(lines) < 210 {
		lines = append(lines, base...)
	}
	content := strings.Join(lines, "\n")
	lower := make([]string, len(lines))
	for i, l := range lines {
		lower[i] = strings.ToLower(l)
	}
	return &rules.ScanContext{
		FilePath:     "/app/src/main/java/Controller.java",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangJava,
	}
}

// javaBenchRules returns every registered Java rule (BATOU-JAVA-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func javaBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-JAVA-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigJavaBench = lowermigCtx([]string{
	"public class UserController {",
	"  public String handle(HttpServletRequest request) throws Exception {",
	"    String name = request.getParameter(\"name\");",
	"    Object o = ctx.lookup(\"ldap://\" + name);",
	"    Query q = session.createQuery(\"from User where n='\" + name + \"'\");",
	"    Connection c = DriverManager.getConnection(\"jdbc:mysql://h/db?user=a&password=p\");",
	"    Velocity.evaluate(ctx, w, \"tag\", name);",
	"    Random r = new java.util.Random();",
	"    URL u = new URL(\"http://\" + name);",
	"    Pattern p = Pattern.compile(name);",
	"    e.printStackTrace(response.getWriter());",
	"    Cookie ck = new Cookie(\"sid\", token);",
	"    new SimpleDateFormat(\"yyyy\");",
	"    int total = items.stream().mapToInt(Item::amount).sum();",
	"    for (Item it : list) { acc.add(it.getName()); }",
	"    if (cfg.isEnabled() && cfg.getTimeout() > 0) { retry(); }",
	"    log.info(\"processed {} records\", count);",
	"    return new ResponseEntity<>(body, HttpStatus.OK);",
	"  }",
	"}",
})

// BenchmarkJavaScan_LowerMigrated runs every Java rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration java/*.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkJavaScan_LowerMigrated(b *testing.B) {
	rs := javaBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigJavaBench))
		}
	}
	_ = n
}
