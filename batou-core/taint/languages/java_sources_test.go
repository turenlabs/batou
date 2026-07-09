package languages

import (
	"regexp"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestJavaFrameworkSources_PRBBjava pins the new framework-aware Java
// sources added by PR-BBjava — Spring MVC / Spring Boot, JAX-RS
// (Jersey, RESTEasy), Micronaut, Quarkus RESTEasy Reactive. Mirrors
// the corresponding test in javascript_sources_test.go.
//
// For each new entry: confirm it is registered on the Java catalog,
// has the expected source category, has a valid Go RE2 regex, matches
// canonical positive shapes, and rejects obvious negatives.
func TestJavaFrameworkSources_PRBBjava(t *testing.T) {
	cases := []struct {
		id        string
		positives []string
		negatives []string
		category  taint.SourceCategory
	}{
		// --- Spring MVC / Spring Boot ---
		{
			id:        "java.spring.modelattribute",
			positives: []string{"public String save(@ModelAttribute User user) {", "@ModelAttribute(\"u\") User u"},
			negatives: []string{"@ModelAttributeFoo()", "ModelAttribute (no @)"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.spring.requestpart",
			positives: []string{"public void up(@RequestPart MultipartFile file)", "@RequestPart(\"avatar\") byte[] b"},
			negatives: []string{"@RequestPartial"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.spring.sessionattribute",
			positives: []string{"public void s(@SessionAttribute(\"u\") User u)"},
			negatives: []string{"@SessionAttributes(\"u\")"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.spring.requestattribute",
			positives: []string{"public void r(@RequestAttribute(\"u\") User u)"},
			negatives: []string{"@RequestAttributes"},
			category:  taint.SrcUserInput,
		},

		// --- JAX-RS ---
		{
			id:        "java.jaxrs.matrixparam",
			positives: []string{"public String m(@MatrixParam(\"m\") String m)"},
			negatives: []string{"@MatrixParamFoo"},
			category:  taint.SrcUserInput,
		},

		// --- Micronaut ---
		{
			id:        "java.micronaut.header",
			positives: []string{"public String h(@Header(\"X-User\") String user)", "@Header String userHeader"},
			negatives: []string{"@HeaderParam(\"X\")"}, // JAX-RS variant — covered by java.jaxrs.headerparam
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.micronaut.body",
			positives: []string{"public Post p(@Body LoginReq r)", "@Body String raw"},
			negatives: []string{"@RequestBody Post p"}, // Spring variant
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.micronaut.part",
			positives: []string{"public void up(@Part CompletedFileUpload file)"},
			negatives: []string{"@Particular"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.micronaut.cookievalue",
			positives: []string{"public String c(@CookieValue String token)"},
			negatives: []string{},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.micronaut.requestbean",
			positives: []string{"public void r(@RequestBean MyBean b)"},
			negatives: []string{},
			category:  taint.SrcUserInput,
		},

		// --- Quarkus RESTEasy Reactive ---
		{
			id:        "java.quarkus.restquery",
			positives: []string{"public String q(@RestQuery String q)", "@RestQuery(\"q\") String x"},
			negatives: []string{"@RestQueryStripped"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.quarkus.restpath",
			positives: []string{"public String p(@RestPath String id)"},
			negatives: []string{"@RestPathway"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.quarkus.restheader",
			positives: []string{"public String h(@RestHeader String h)"},
			negatives: []string{"@RestHeaderPlus"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.quarkus.restcookie",
			positives: []string{"public String c(@RestCookie String t)"},
			negatives: []string{},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.quarkus.restform",
			positives: []string{"public void f(@RestForm String body)"},
			negatives: []string{"@RestFormat"},
			category:  taint.SrcUserInput,
		},
		{
			id:        "java.quarkus.restmatrix",
			positives: []string{"public void m(@RestMatrix String m)"},
			negatives: []string{},
			category:  taint.SrcUserInput,
		},
	}

	byID := map[string]taint.SourceDef{}
	for _, s := range taint.SourcesForLanguage(rules.LangJava) {
		byID[s.ID] = s
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got, ok := byID[c.id]
			if !ok {
				t.Fatalf("Java source %s not registered", c.id)
			}
			if got.Category != c.category {
				t.Errorf("Java source %s: category=%v, want %v", c.id, got.Category, c.category)
			}
			re, err := regexp.Compile(got.Pattern)
			if err != nil {
				t.Fatalf("Java source %s: regex compile error: %v", c.id, err)
			}
			for _, p := range c.positives {
				if !re.MatchString(p) {
					t.Errorf("Java source %s: expected pattern %q to match %q", c.id, got.Pattern, p)
				}
			}
			for _, n := range c.negatives {
				if re.MatchString(n) {
					t.Errorf("Java source %s: expected pattern %q to NOT match %q", c.id, got.Pattern, n)
				}
			}
		})
	}
}

// TestJavaSanitizers_PRBBjava verifies the new Pattern.matches
// sanitizer landed. The other sanitizers requested by the spec
// (HtmlUtils, StringEscapeUtils.escapeHtml4, URLEncoder.encode,
// UriComponentsBuilder) were already in the catalog.
func TestJavaSanitizers_PRBBjava(t *testing.T) {
	sans := taint.SanitizersForLanguage(rules.LangJava)
	want := []string{
		"java.regex.pattern.matches",
		// Pre-existing — verify they're still present so a refactor
		// can't silently drop them.
		"java.spring.htmlutils.htmlescape",
		"java.stringescapeutils.escapehtml4",
		"java.urlencoder.encode",
		"java.spring.uricomponentsbuilder",
	}
	idx := map[string]taint.SanitizerDef{}
	for _, s := range sans {
		idx[s.ID] = s
	}
	for _, id := range want {
		if _, ok := idx[id]; !ok {
			t.Errorf("expected Java sanitizer %s in catalog", id)
		}
	}

	// Pattern.matches must require the first arg to be a string literal
	// — otherwise any Pattern.matches(...) call would be misread as a
	// sanitizer.
	pm := idx["java.regex.pattern.matches"]
	re, err := regexp.Compile(pm.Pattern)
	if err != nil {
		t.Fatalf("Pattern.matches regex compile error: %v", err)
	}
	if !re.MatchString(`Pattern.matches("^[a-z]+$", input)`) {
		t.Errorf("Pattern.matches should match a literal-regex call")
	}
	if re.MatchString(`Pattern.matches(userRegex, input)`) {
		t.Errorf("Pattern.matches should NOT match a non-literal first arg")
	}
}
