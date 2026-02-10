package taint

import (
	"testing"

	"github.com/turen/gtss/internal/rules"
)

func TestDetectScopes(t *testing.T) {
	tests := []struct {
		name      string
		lang      rules.Language
		code      string
		wantName  string // expected scope name (one of the scopes)
		wantMin   int    // minimum number of scopes
		wantParam string // expected parameter name (empty = skip check)
	}{
		// Go
		{
			name: "Go simple func",
			lang: rules.LangGo,
			code: `func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "hello")
}`,
			wantName:  "handler",
			wantMin:   1,
			wantParam: "r",
		},
		{
			name: "Go method receiver",
			lang: rules.LangGo,
			code: `func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handle(w, r)
}`,
			wantName:  "ServeHTTP",
			wantMin:   1,
			wantParam: "r",
		},

		// Python
		{
			name: "Python def with request",
			lang: rules.LangPython,
			code: `def login(request):
    user = request.POST.get("user")
    return authenticate(user)
`,
			wantName:  "login",
			wantMin:   1,
			wantParam: "request",
		},
		{
			name: "Python async def",
			lang: rules.LangPython,
			code: `async def fetch_data(url):
    resp = await aiohttp.get(url)
    return resp
`,
			wantName:  "fetch_data",
			wantMin:   1,
			wantParam: "url",
		},
		{
			name: "Python self is filtered",
			lang: rules.LangPython,
			code: `def update(self, data):
    self.data = data
`,
			wantName: "update",
			wantMin:  1,
		},

		// JavaScript
		{
			name: "JS function declaration",
			lang: rules.LangJavaScript,
			code: `function search(req, res) {
	const q = req.query.q;
	res.send(q);
}`,
			wantName:  "search",
			wantMin:   1,
			wantParam: "req",
		},
		{
			name: "JS export function",
			lang: rules.LangJavaScript,
			code: `export function search(req, res) {
	const q = req.query.q;
	res.send(q);
}`,
			wantName:  "search",
			wantMin:   1,
			wantParam: "req",
		},
		{
			name: "JS Express router handler",
			lang: rules.LangJavaScript,
			code: `router.get('/search', (req, res) => {
	const q = req.query.q;
	res.json({ results: q });
})`,
			wantName:  "router.get",
			wantMin:   1,
			wantParam: "req",
		},
		{
			name: "JS const arrow function",
			lang: rules.LangJavaScript,
			code: `const handleRequest = async (req, res) => {
	const data = req.body;
	res.send(data);
}`,
			wantName: "handleRequest",
			wantMin:  1,
		},

		// Java
		{
			name: "Java servlet doGet",
			lang: rules.LangJava,
			code: `public void doGet(HttpServletRequest req, HttpServletResponse resp) {
	String user = req.getParameter("user");
	resp.getWriter().write(user);
}`,
			wantName: "doGet",
			wantMin:  1,
		},
		{
			name: "Java public method",
			lang: rules.LangJava,
			code: `public String processInput(String data) {
	return data.trim();
}`,
			wantName: "processInput",
			wantMin:  1,
		},

		// C
		{
			name: "C main function",
			lang: rules.LangC,
			code: `int main(int argc, char *argv[]) {
	printf("hello\n");
	return 0;
}`,
			wantName: "main",
			wantMin:  1,
		},
		{
			name: "C void function",
			lang: rules.LangC,
			code: `void process_input(char *buf, size_t len) {
	memcpy(dest, buf, len);
}`,
			wantName: "process_input",
			wantMin:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := DetectScopes(tt.code, tt.lang)

			if len(scopes) < tt.wantMin {
				t.Fatalf("expected at least %d scopes, got %d", tt.wantMin, len(scopes))
			}

			found := false
			var matchedScope *Scope
			for i, sc := range scopes {
				if sc.Name == tt.wantName {
					found = true
					matchedScope = &scopes[i]
					break
				}
			}
			if !found {
				names := make([]string, len(scopes))
				for i, sc := range scopes {
					names[i] = sc.Name
				}
				t.Errorf("expected scope named %q, got %v", tt.wantName, names)
				return
			}

			if tt.wantParam != "" && matchedScope != nil {
				paramFound := false
				for _, p := range matchedScope.Params {
					if p == tt.wantParam {
						paramFound = true
						break
					}
				}
				if !paramFound {
					t.Errorf("expected param %q in scope %q, got %v", tt.wantParam, tt.wantName, matchedScope.Params)
				}
			}
		})
	}
}

func TestDetectScopesNestedFunctions(t *testing.T) {
	code := `func outer(w http.ResponseWriter, r *http.Request) {
	go func() {
		inner()
	}()
	fmt.Fprintln(w, "done")
}`
	scopes := DetectScopes(code, rules.LangGo)

	if len(scopes) < 1 {
		t.Fatalf("expected at least 1 scope, got %d", len(scopes))
	}

	found := false
	for _, sc := range scopes {
		if sc.Name == "outer" {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, len(scopes))
		for i, sc := range scopes {
			names[i] = sc.Name
		}
		t.Errorf("expected scope named 'outer', got %v", names)
	}
}

func TestDetectScopesPythonIndentation(t *testing.T) {
	code := `def outer():
    x = 1

def inner():
    y = 2
`
	scopes := DetectScopes(code, rules.LangPython)

	outerFound := false
	innerFound := false
	for _, sc := range scopes {
		if sc.Name == "outer" {
			outerFound = true
		}
		if sc.Name == "inner" {
			innerFound = true
		}
	}
	if !outerFound {
		t.Error("expected scope 'outer'")
	}
	if !innerFound {
		t.Error("expected scope 'inner'")
	}
}

func TestDetectScopesRuby(t *testing.T) {
	code := `def process(input)
  sanitized = input.strip
  return sanitized
end
`
	scopes := DetectScopes(code, rules.LangRuby)

	found := false
	for _, sc := range scopes {
		if sc.Name == "process" {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, len(scopes))
		for i, sc := range scopes {
			names[i] = sc.Name
		}
		t.Errorf("expected scope 'process', got %v", names)
	}
}

func TestExtractParamNames(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"(w http.ResponseWriter, r *http.Request)", []string{"w", "r"}},
		{"(req, res)", []string{"req", "res"}},
		{"()", nil},
		{"(int argc, char *argv[])", []string{"argc", "argv"}},
		{"(data: string, count: number)", []string{"data", "count"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractParamNames(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("extractParamNames(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractParamNames(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParenBalanced(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"foo(bar)", true},
		{"foo(bar", false},
		{"(a, (b, c))", true},
		{"((()))", true},
		{"((())", false},
		{"no parens", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parenBalanced(tt.input)
			if got != tt.want {
				t.Errorf("parenBalanced(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractAssignmentLHS(t *testing.T) {
	tests := []struct {
		line string
		lang rules.Language
		want string
	}{
		{`x := r.FormValue("a")`, rules.LangGo, "x"},
		{"x, err := something()", rules.LangGo, "x"},
		{"var x = expr", rules.LangJavaScript, "x"},
		{"let y = expr", rules.LangJavaScript, "y"},
		{"const z = expr", rules.LangJavaScript, "z"},
		{"$x = expr", rules.LangPHP, "x"},
		{"name = request.args.get('name')", rules.LangPython, "name"},
		{"if x == y {", rules.LangGo, ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := extractAssignmentLHS(tt.line, tt.lang)
			if got != tt.want {
				t.Errorf("extractAssignmentLHS(%q, %s) = %q, want %q", tt.line, tt.lang, got, tt.want)
			}
		})
	}
}
