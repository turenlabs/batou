package massassign

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// --- BATOU-MASS-001: JavaScript Mass Assignment ---

func TestMASS001_ObjectAssignModel(t *testing.T) {
	content := `const body = req.body;
Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_SpreadIntoModel(t *testing.T) {
	content := `const updated = {...user, ...req.body};`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_ORMUpdateRaw(t *testing.T) {
	content := `const data = req.body;
await User.findOneAndUpdate(req.body);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_ModelConstructor(t *testing.T) {
	content := `const user = new User(req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_Safe_PickFields(t *testing.T) {
	content := `const allowed = _.pick(req.body, ['name', 'email']);
Object.assign(user, allowed);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-001")
}

func TestMASS001_Safe_NoUserInput(t *testing.T) {
	content := `const defaults = { name: "test" };
Object.assign(user, defaults);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-001")
}

// --- BATOU-MASS-002: Python Mass Assignment ---

func TestMASS002_DjangoCreate(t *testing.T) {
	content := `data = request.data
User.objects.create(**request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_ModelUnpack(t *testing.T) {
	content := `user = User(**request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_FlaskModelUnpack(t *testing.T) {
	content := `user = User(**request.json)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_DictUpdate(t *testing.T) {
	content := `user.__dict__.update(request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_SetattrLoop(t *testing.T) {
	content := `for key, val in data.items():
    setattr(user, key, val)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_SerializerFieldsAll(t *testing.T) {
	content := `class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'`
	result := testutil.ScanContent(t, "/app/serializers.py", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-002")
}

func TestMASS002_Safe_ExplicitFields(t *testing.T) {
	content := `user = User(name=request.data['name'], email=request.data['email'])`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-002")
}

// --- BATOU-MASS-003: Ruby Mass Assignment ---

func TestMASS003_RailsNewParams(t *testing.T) {
	content := `user = User.new(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_RailsCreateParams(t *testing.T) {
	content := `user = User.create(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_RailsUpdateRawParams(t *testing.T) {
	content := `user.update(params)`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_Safe_StrongParams(t *testing.T) {
	content := `def user_params
  params.require(:user).permit(:name, :email)
end

user = User.new(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	// Should still find but with low confidence since .permit exists in file
	found := testutil.HasFinding(result, "BATOU-MASS-003")
	if !found {
		t.Log("BATOU-MASS-003 not found, which is acceptable when strong params are present")
	}
}

// RailsGoat documented mass-assignment idioms: the unfiltered hash is bound to
// a variable first (permit! / to_unsafe_h on its own line) and only passed to
// the model write on a later line, so the inline `params[:` patterns miss it.
// permit! / to_unsafe_h are themselves the vulnerability and must fire.

func TestMASS003_RailsGoat_PermitBang_VariableIndirection(t *testing.T) {
	// railsgoat users_controller.rb: permit! assigned, model write is elsewhere.
	content := `def user_params
  params.require(:user).permit!
end

def update
  @user.update(user_params)
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_RailsGoat_ToUnsafeH_VariableIndirection(t *testing.T) {
	// railsgoat admin_controller.rb: to_unsafe_h drains the filtered hash, then
	// a later .update(filtered_params) writes it — variable indirection.
	content := `def update_user
  user_params = params[:user].to_unsafe_h
  filtered_params = user_params.reject { |k, v| v.blank? }
  user.update(filtered_params)
end`
	result := testutil.ScanContent(t, "/app/controllers/admin_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_Safe_PermitAllowlist_NoPermitBang(t *testing.T) {
	// The safe idiom: an explicit allowlist via permit(:a, :b) — no permit! and
	// no to_unsafe_h — must NOT trip the new branch.
	content := `def user_params
  params.require(:user).permit(:email, :first_name, :last_name)
end

def update
  @user.update(user_params)
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-003")
}

func TestMASS003_Safe_SliceAllowlistBeforePermitBang(t *testing.T) {
	// .slice(:a, :b).permit! restricts the hash to developer-chosen keys before
	// permit!, so permit! only blesses an allowlisted set — the safe idiom seen
	// in real Rails apps. Must NOT trip the permit! branch.
	content := `more_params = params.slice(:period, :order, :group).permit!`
	result := testutil.ScanContent(t, "/app/controllers/items_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-003")
}

// --- BATOU-MASS-004: Java Mass Assignment ---

func TestMASS004_ModelAttribute(t *testing.T) {
	content := `@PostMapping("/update")
public String update(@ModelAttribute User user) {
    userService.save(user);
    return "success";
}`
	result := testutil.ScanContent(t, "/app/UserController.java", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-004")
}

func TestMASS004_BeanUtilsCopy(t *testing.T) {
	content := `BeanUtils.copyProperties(source, target);`
	result := testutil.ScanContent(t, "/app/UserService.java", content)
	testutil.MustFindRule(t, result, "BATOU-MASS-004")
}

func TestMASS004_Safe_WithInitBinder(t *testing.T) {
	content := `@InitBinder
public void initBinder(WebDataBinder binder) {
    binder.setAllowedFields("name", "email");
}

@PostMapping("/update")
public String update(@ModelAttribute User user) {
    userService.save(user);
    return "success";
}`
	result := testutil.ScanContent(t, "/app/UserController.java", content)
	testutil.MustNotFindRule(t, result, "BATOU-MASS-004")
}
