package massassign

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-rules/testutil"
)

// ---------------------------------------------------------------------------
// Metadata coverage: Name()/Description() on every rule (0% before).
// ---------------------------------------------------------------------------

func TestMassAssign_Metadata(t *testing.T) {
	allRules := []rules.Rule{
		&MassAssignJS{},
		&MassAssignPython{},
		&MassAssignRuby{},
		&MassAssignJava{},
		&DjangoModelFormNoFields{},
		&SpringModelAttrNoInitBinder{},
		&ExpressBodyToDB{},
		&AspNetModelBindingNoBind{},
		&GoStructBindNoTags{},
		&PHPEloquentGuardedEmpty{},
	}
	type named interface {
		Name() string
		Description() string
	}
	for _, r := range allRules {
		if r.ID() == "" {
			t.Errorf("rule has empty ID")
		}
		if r.DefaultSeverity().String() == "" {
			t.Errorf("%s: empty severity", r.ID())
		}
		if len(r.Languages()) == 0 {
			t.Errorf("%s: no languages", r.ID())
		}
		n := r.(named)
		if n.Name() == "" {
			t.Errorf("%s: empty Name()", r.ID())
		}
		if n.Description() == "" {
			t.Errorf("%s: empty Description()", r.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// BATOU-MASS-001 JS — extra branches (spread title, comment skip, full finding fields)
// ---------------------------------------------------------------------------

func TestMASS001_FindingFields(t *testing.T) {
	content := `Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	fs := testutil.FindingsByRule(result, "BATOU-MASS-001")
	if len(fs) == 0 {
		t.Fatalf("expected MASS-001 finding")
	}
	f := fs[0]
	if f.CWEID != "CWE-915" {
		t.Errorf("CWE = %q, want CWE-915", f.CWEID)
	}
	if f.SeverityLabel != rules.High.String() {
		t.Errorf("severity = %q, want High", f.SeverityLabel)
	}
	if f.Confidence != "high" {
		t.Errorf("confidence = %q, want high", f.Confidence)
	}
}

func TestMASS001_CommentLineSkipped(t *testing.T) {
	content := `// Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_Safe_AllowedFieldsKeyword(t *testing.T) {
	// hasFieldWhitelist should fire on "allowedFields"
	content := `const allowedFields = ['name'];
Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_Safe_SanitizeKeyword(t *testing.T) {
	content := `const clean = sanitize(req.body);
Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-001")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-002 Python — comment skip + safe serializer (no fields=__all__)
// ---------------------------------------------------------------------------

func TestMASS002_CommentSkipped(t *testing.T) {
	content := `# User.objects.create(**request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_Safe_SerializerExplicitFields(t *testing.T) {
	// Serializer class present but fields is an explicit list, not __all__.
	content := `class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email']`
	result := testutil.ScanContent(t, "/app/serializers.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_SetattrLoop_NotInLoop_NoFinding(t *testing.T) {
	// setattr matches pySetattrLoop but isInLoop is false (no for/.items/.each nearby).
	content := `setattr(user, key, value)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-002")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-003 Ruby — low-confidence branch (permit present) + comment skip
// ---------------------------------------------------------------------------

func TestMASS003_LowConfidence_WithPermitInFile(t *testing.T) {
	// .permit exists in file → rbModelNewParams hits the low-confidence branch.
	content := `def user_params
  params.require(:user).permit(:name, :email)
end

def create
  user = User.new(params[:user])
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	fs := testutil.FindingsByRule(result, "BATOU-MASS-003")
	if len(fs) == 0 {
		t.Fatalf("expected MASS-003 finding (low confidence)")
	}
	foundLow := false
	for _, f := range fs {
		if f.Confidence == "low" {
			foundLow = true
		}
	}
	if !foundLow {
		t.Errorf("expected at least one low-confidence MASS-003 finding, got %+v", fs)
	}
}

func TestMASS003_CommentSkipped(t *testing.T) {
	content := `# user = User.new(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_AssignAttributesRaw(t *testing.T) {
	content := `user.assign_attributes(params)`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-003")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-004 Java — BeanUtils medium-severity branch + comment skip
// ---------------------------------------------------------------------------

func TestMASS004_BeanUtilsSeverityMedium(t *testing.T) {
	content := `BeanUtils.copyProperties(source, target);`
	result := testutil.ScanContent(t, "/app/UserService.java", content)
	fs := testutil.FindingsByRule(result, "BATOU-MASS-004")
	if len(fs) == 0 {
		t.Fatalf("expected MASS-004 finding")
	}
	if fs[0].SeverityLabel != rules.Medium.String() {
		t.Errorf("BeanUtils severity = %q, want Medium", fs[0].SeverityLabel)
	}
}

func TestMASS004_CommentSkipped(t *testing.T) {
	content := `// @ModelAttribute User user`
	result := testutil.ScanContent(t, "/app/UserController.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-004")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-005 Django ModelForm without Meta.fields
// ---------------------------------------------------------------------------

func TestMASS005_FieldsAll(t *testing.T) {
	content := `class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = '__all__'`
	result := testutil.ScanContent(t, "/app/forms.py", content)
	fs := testutil.FindingsByRule(result, "BATOU-MASS-005")
	if len(fs) == 0 {
		t.Fatalf("expected MASS-005 finding, got %v", testutil.FindingRuleIDs(result))
	}
	if !strings.Contains(fs[0].Title, "fields='__all__'") {
		t.Errorf("title = %q, want fields='__all__'", fs[0].Title)
	}
}

func TestMASS005_ExcludeEmpty(t *testing.T) {
	content := `class UserForm(ModelForm):
    class Meta:
        model = User
        exclude = []`
	result := testutil.ScanContent(t, "/app/forms.py", content)
	fs := testutil.FindingsByRule(result, "BATOU-MASS-005")
	if len(fs) == 0 {
		t.Fatalf("expected MASS-005 finding (exclude=[]), got %v", testutil.FindingRuleIDs(result))
	}
	if !strings.Contains(fs[0].Title, "exclude=[]") {
		t.Errorf("title = %q, want exclude=[]", fs[0].Title)
	}
}

func TestMASS005_Safe_ExplicitFields(t *testing.T) {
	content := `class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['name', 'email']`
	result := testutil.ScanContent(t, "/app/forms.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-005")
}

func TestMASS005_CommentSkipped(t *testing.T) {
	// The ModelForm class line is a comment → rule never enters the body.
	content := `# class UserForm(forms.ModelForm):
#    fields = '__all__'`
	result := testutil.ScanContent(t, "/app/forms.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-005")
}

func TestMASS005_LongMatchTruncated(t *testing.T) {
	// fieldsMatch > 120 chars → truncation branch in MASS-005.
	pad := strings.Repeat("x", 200)
	content := `class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = '__all__'  # ` + pad
	result := testutil.ScanContent(t, "/app/forms.py", content)
	fs := testutil.FindingsByRule(result, "BATOU-MASS-005")
	if len(fs) == 0 {
		t.Fatalf("expected MASS-005 finding")
	}
	if !strings.HasSuffix(fs[0].MatchedText, "...") {
		t.Errorf("expected truncated matched text, got %q", fs[0].MatchedText)
	}
}

// ---------------------------------------------------------------------------
// BATOU-MASS-006 Spring @ModelAttribute without @InitBinder
// ---------------------------------------------------------------------------

func TestMASS006_ModelAttrNoInitBinder(t *testing.T) {
	content := `@PostMapping("/u")
public String save(@ModelAttribute User user) {
    return "ok";
}`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-006")
}

func TestMASS006_Safe_InitBinderAllowedFields(t *testing.T) {
	// @InitBinder + setAllowedFields → rule returns nil early.
	content := `@InitBinder
public void init(WebDataBinder binder) {
    binder.setAllowedFields("name", "email");
}
public String save(@ModelAttribute User user) {
    return "ok";
}`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-006")
}

func TestMASS006_Safe_InitBinderDisallowedFields(t *testing.T) {
	content := `@InitBinder
public void init(WebDataBinder binder) {
    binder.setDisallowedFields("isAdmin");
}
public String save(@ModelAttribute User user) {
    return "ok";
}`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-006")
}

func TestMASS006_InitBinderWithoutFieldRestriction_StillFlags(t *testing.T) {
	// @InitBinder present but no setAllowedFields/setDisallowedFields → not safe.
	content := `@InitBinder
public void init(WebDataBinder binder) {
    binder.registerCustomEditor(Date.class, editor);
}
public String save(@ModelAttribute User user) {
    return "ok";
}`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-006")
}

func TestMASS006_NoModelAttribute_NoFinding(t *testing.T) {
	content := `public String save(User user) { return "ok"; }`
	result := testutil.ScanContent(t, "/app/Controller.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-006")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-007 Express body → DB
// ---------------------------------------------------------------------------

func TestMASS007_BodyToDB(t *testing.T) {
	content := `await User.create(req.body)`
	result := testutil.ScanContent(t, "/app/route.js", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-007")
}

func TestMASS007_SpreadBodyToDB(t *testing.T) {
	content := `await User.update({...req.body})`
	result := testutil.ScanContent(t, "/app/route.ts", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-007")
}

func TestMASS007_Safe_WhitelistNearby(t *testing.T) {
	content := `const data = _.pick(req.body, ['name']);
await User.create(req.body)`
	result := testutil.ScanContent(t, "/app/route.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-007")
}

func TestMASS007_CommentSkipped(t *testing.T) {
	content := `// await User.create(req.body)`
	result := testutil.ScanContent(t, "/app/route.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-007")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-008 ASP.NET model binding without [Bind]
// ---------------------------------------------------------------------------

func TestMASS008_ActionNoBind(t *testing.T) {
	content := `public IActionResult Create(User user)
{
    db.Save(user);
}`
	result := testutil.ScanContent(t, "/app/UsersController.cs", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-008")
}

func TestMASS008_Safe_BindPresent(t *testing.T) {
	// [Bind] anywhere in file → rule returns nil early.
	content := `public IActionResult Create([Bind("Name,Email")] User user)
{
    db.Save(user);
}`
	result := testutil.ScanContent(t, "/app/UsersController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-008")
}

func TestMASS008_Safe_BindNeverPresent(t *testing.T) {
	content := `[BindNever]
public string Secret { get; set; }

public IActionResult Create(User user)
{
    db.Save(user);
}`
	result := testutil.ScanContent(t, "/app/UsersController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-008")
}

func TestMASS008_Safe_FromBodyOnLine(t *testing.T) {
	// Action line itself uses [FromBody] → the per-line gate skips it.
	content := `public IActionResult Create([FromBody] User user)
{
    db.Save(user);
}`
	result := testutil.ScanContent(t, "/app/UsersController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-008")
}

func TestMASS008_CommentSkipped(t *testing.T) {
	content := `// public IActionResult Create(User user)`
	result := testutil.ScanContent(t, "/app/UsersController.cs", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-008")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-009 Go struct binding without field tags
// ---------------------------------------------------------------------------

func TestMASS009_JSONBindHTTPHandler(t *testing.T) {
	content := `func Handler(w http.ResponseWriter, r *http.Request) {
    var u User
    json.NewDecoder(r.Body).Decode(&u)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-009")
}

func TestMASS009_Safe_JSONDashTag(t *testing.T) {
	// json:"-" present → rule returns nil.
	content := `type User struct {
    Name  string ` + "`json:\"name\"`" + `
    Admin bool   ` + "`json:\"-\"`" + `
}
func Handler(w http.ResponseWriter, r *http.Request) {
    var u User
    json.NewDecoder(r.Body).Decode(&u)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-009")
}

func TestMASS009_Safe_NoHTTPHandler(t *testing.T) {
	// JSON bind but no HTTP handler context → gated off.
	content := `func LoadConfig(path string) error {
    var c Config
    return json.Unmarshal(data, &c)
}`
	result := testutil.ScanContent(t, "/app/config.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-009")
}

func TestMASS009_Safe_NoJSONBind(t *testing.T) {
	content := `func Handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "ok")
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-009")
}

func TestMASS009_GinShouldBindJSON(t *testing.T) {
	content := `func Create(c *gin.Context) {
    var u User
    c.ShouldBindJSON(&u)
}`
	result := testutil.ScanContent(t, "/app/handler.go", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-009")
}

// ---------------------------------------------------------------------------
// BATOU-MASS-010 PHP Eloquent $guarded = []
// ---------------------------------------------------------------------------

func TestMASS010_GuardedEmpty(t *testing.T) {
	content := `<?php
class User extends Model {
    protected $guarded = [];
}`
	result := testutil.ScanContent(t, "/app/User.php", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-010")
}

func TestMASS010_Safe_Fillable(t *testing.T) {
	content := `<?php
class User extends Model {
    protected $fillable = ['name', 'email'];
}`
	result := testutil.ScanContent(t, "/app/User.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-010")
}

func TestMASS010_Safe_GuardedNonEmpty(t *testing.T) {
	content := `<?php
class User extends Model {
    protected $guarded = ['id', 'is_admin'];
}`
	result := testutil.ScanContent(t, "/app/User.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-010")
}

func TestMASS010_CommentSkipped(t *testing.T) {
	content := `# protected $guarded = [];`
	result := testutil.ScanContent(t, "/app/User.php", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-010")
}

// ---------------------------------------------------------------------------
// Helper coverage: truncate, hasFieldWhitelist, isInLoop, isComment.
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	if got := truncate("short", 120); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	long := strings.Repeat("a", 130)
	got := truncate(long, 120)
	if len(got) != 123 { // 120 + "..."
		t.Errorf("truncate long len = %d, want 123", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncate long missing ellipsis: %q", got)
	}
}

func TestHasFieldWhitelist(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		idx   int
		want  bool
	}{
		{"whitelist", []string{"const whitelist = [];", "Object.assign(u, req.body);"}, 1, true},
		{"allowlist", []string{"const allowlist = [];", "x"}, 1, true},
		{"allowed_fields", []string{"allowed_fields = []", "x"}, 1, true},
		{"_.pick", []string{"_.pick(b)", "x"}, 1, true},
		{"filterfields", []string{"filterFields(b)", "x"}, 1, true},
		{"filter_fields", []string{"filter_fields(b)", "x"}, 1, true},
		{"none", []string{"plain line", "another"}, 1, false},
		{"idx_zero", []string{"Object.assign(u, req.body)"}, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasFieldWhitelist(c.lines, c.idx); got != c.want {
				t.Errorf("hasFieldWhitelist = %v, want %v", got, c.want)
			}
		})
	}
}

func TestIsInLoop(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		idx   int
		want  bool
	}{
		{"for_space", []string{"for x in y:", "setattr(o,k,v)"}, 1, true},
		{"for_paren", []string{"for(int i=0;;)", "x"}, 1, true},
		{"items", []string{"for k,v in d.items():", "x"}, 1, true},
		{"each", []string{"data.each do |k|", "x"}, 1, true},
		{"none", []string{"x = 1", "setattr(o,k,v)"}, 1, false},
		{"idx_zero_clamps", []string{"for x in y:"}, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isInLoop(c.lines, c.idx); got != c.want {
				t.Errorf("isInLoop = %v, want %v", got, c.want)
			}
		})
	}
}

func TestIsComment(t *testing.T) {
	truthy := []string{"// x", "# x", "* x", "/* x", "<!-- x"}
	for _, s := range truthy {
		if !isComment(s) {
			t.Errorf("isComment(%q) = false, want true", s)
		}
	}
	if isComment("code();") {
		t.Errorf("isComment(code) = true, want false")
	}
}
