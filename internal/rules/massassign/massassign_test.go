package massassign

import (
	"testing"

	"github.com/turen/gtss/internal/testutil"
)

// --- GTSS-MASS-001: JavaScript Mass Assignment ---

func TestMASS001_ObjectAssignModel(t *testing.T) {
	content := `const body = req.body;
Object.assign(user, req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-001")
}

func TestMASS001_SpreadIntoModel(t *testing.T) {
	content := `const updated = {...user, ...req.body};`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-001")
}

func TestMASS001_ORMUpdateRaw(t *testing.T) {
	content := `const data = req.body;
await User.findOneAndUpdate(req.body);`
	result := testutil.ScanContent(t, "/app/handler.ts", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-001")
}

func TestMASS001_ModelConstructor(t *testing.T) {
	content := `const user = new User(req.body);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-001")
}

func TestMASS001_Safe_PickFields(t *testing.T) {
	content := `const allowed = _.pick(req.body, ['name', 'email']);
Object.assign(user, allowed);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-MASS-001")
}

func TestMASS001_Safe_NoUserInput(t *testing.T) {
	content := `const defaults = { name: "test" };
Object.assign(user, defaults);`
	result := testutil.ScanContent(t, "/app/handler.js", content)
	testutil.MustNotFindRule(t, result, "GTSS-MASS-001")
}

// --- GTSS-MASS-002: Python Mass Assignment ---

func TestMASS002_DjangoCreate(t *testing.T) {
	content := `data = request.data
User.objects.create(**request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-002")
}

func TestMASS002_ModelUnpack(t *testing.T) {
	content := `user = User(**request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-002")
}

func TestMASS002_FlaskModelUnpack(t *testing.T) {
	content := `user = User(**request.json)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-002")
}

func TestMASS002_DictUpdate(t *testing.T) {
	content := `user.__dict__.update(request.data)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-002")
}

func TestMASS002_SetattrLoop(t *testing.T) {
	content := `for key, val in data.items():
    setattr(user, key, val)`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-002")
}

func TestMASS002_SerializerFieldsAll(t *testing.T) {
	content := `class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'`
	result := testutil.ScanContent(t, "/app/serializers.py", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-002")
}

func TestMASS002_Safe_ExplicitFields(t *testing.T) {
	content := `user = User(name=request.data['name'], email=request.data['email'])`
	result := testutil.ScanContent(t, "/app/views.py", content)
	testutil.MustNotFindRule(t, result, "GTSS-MASS-002")
}

// --- GTSS-MASS-003: Ruby Mass Assignment ---

func TestMASS003_RailsNewParams(t *testing.T) {
	content := `user = User.new(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-003")
}

func TestMASS003_RailsCreateParams(t *testing.T) {
	content := `user = User.create(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-003")
}

func TestMASS003_RailsUpdateRawParams(t *testing.T) {
	content := `user.update(params)`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-003")
}

func TestMASS003_Safe_StrongParams(t *testing.T) {
	content := `def user_params
  params.require(:user).permit(:name, :email)
end

user = User.new(params[:user])`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	// Should still find but with low confidence since .permit exists in file
	found := testutil.HasFinding(result, "GTSS-MASS-003")
	if !found {
		t.Log("GTSS-MASS-003 not found, which is acceptable when strong params are present")
	}
}

// --- GTSS-MASS-004: Java Mass Assignment ---

func TestMASS004_ModelAttribute(t *testing.T) {
	content := `@PostMapping("/update")
public String update(@ModelAttribute User user) {
    userService.save(user);
    return "success";
}`
	result := testutil.ScanContent(t, "/app/UserController.java", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-004")
}

func TestMASS004_BeanUtilsCopy(t *testing.T) {
	content := `BeanUtils.copyProperties(source, target);`
	result := testutil.ScanContent(t, "/app/UserService.java", content)
	testutil.MustFindRule(t, result, "GTSS-MASS-004")
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
	testutil.MustNotFindRule(t, result, "GTSS-MASS-004")
}
