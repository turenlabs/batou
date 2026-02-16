package ruby

import (
	"testing"

	"github.com/turenlabs/batou/internal/testutil"
)

// ==========================================================================
// BATOU-RB-001: ERB Output Without Escaping
// ==========================================================================

func TestRB001_RawWithParams(t *testing.T) {
	content := `class UsersController < ApplicationController
  def show
    @content = raw(params[:content])
  end
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-001")
}

func TestRB001_HTMLSafeOnParams(t *testing.T) {
	content := `class PostsController < ApplicationController
  def show
    @html = params[:body].html_safe
  end
end`
	result := testutil.ScanContent(t, "/app/controllers/posts_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-001")
}

func TestRB001_HTMLSafeOnInterpolation(t *testing.T) {
	content := `def render_message
  "<div>#{user_input}</div>".html_safe
end`
	result := testutil.ScanContent(t, "/app/helpers/display_helper.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-001")
}

func TestRB001_SanitizeHelper_Safe(t *testing.T) {
	content := `class PostsController < ApplicationController
  def show
    @html = sanitize(params[:body])
  end
end`
	result := testutil.ScanContent(t, "/app/controllers/posts_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-001")
}

// ==========================================================================
// BATOU-RB-002: Command Injection
// ==========================================================================

func TestRB002_SystemWithParamsInterpolation(t *testing.T) {
	content := `def convert(file)
  system("convert #{params[:filename]} output.png")
end`
	result := testutil.ScanContent(t, "/app/services/converter.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-002")
}

func TestRB002_SystemWithRequestVar(t *testing.T) {
	content := `def ping
  system(request.params[:host])
end`
	result := testutil.ScanContent(t, "/app/controllers/network_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-002")
}

func TestRB002_BacktickWithParams(t *testing.T) {
	content := "def run\n  result = `ls #{params[:dir]}`\nend"
	result := testutil.ScanContent(t, "/app/services/file_service.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-002")
}

func TestRB002_SystemArrayForm_Safe(t *testing.T) {
	content := `def convert(file)
  system("convert", file, "output.png")
end`
	result := testutil.ScanContent(t, "/app/services/converter.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-002")
}

// ==========================================================================
// BATOU-RB-003: YAML.load
// ==========================================================================

func TestRB003_YAMLLoad(t *testing.T) {
	content := `def parse_config(data)
  config = YAML.load(data)
  process(config)
end`
	result := testutil.ScanContent(t, "/app/services/config_parser.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-003")
}

func TestRB003_YAMLLoadFile(t *testing.T) {
	content := `def load_settings
  settings = YAML.load_file(params[:config_path])
end`
	result := testutil.ScanContent(t, "/app/services/settings.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-003")
}

func TestRB003_YAMLSafeLoad_Safe(t *testing.T) {
	content := `def parse_config(data)
  config = YAML.safe_load(data)
  process(config)
end`
	result := testutil.ScanContent(t, "/app/services/config_parser.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-003")
}

// ==========================================================================
// BATOU-RB-004: Sinatra Params in SQL/Shell
// ==========================================================================

func TestRB004_SinatraParamsInSQL(t *testing.T) {
	content := `get '/users' do
  db.execute("SELECT * FROM users WHERE name = '#{params[:name]}'")
end`
	result := testutil.ScanContent(t, "/app/sinatra_app.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-004")
}

func TestRB004_SinatraParamsInShell(t *testing.T) {
	content := `post '/convert' do
  system("convert #{params[:file]} output.png")
end`
	result := testutil.ScanContent(t, "/app/sinatra_app.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-004")
}

func TestRB004_SinatraParamsParameterized_Safe(t *testing.T) {
	content := `get '/users' do
  db.execute("SELECT * FROM users WHERE name = ?", params[:name])
end`
	result := testutil.ScanContent(t, "/app/sinatra_app.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-004")
}

// ==========================================================================
// BATOU-RB-005: Kernel#open with Pipe
// ==========================================================================

func TestRB005_OpenWithParams(t *testing.T) {
	content := `def fetch_file
  data = open(params[:url]).read
end`
	result := testutil.ScanContent(t, "/app/controllers/files_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-005")
}

func TestRB005_OpenWithPipe(t *testing.T) {
	content := `def run_command
  output = open("| ls -la /tmp")
end`
	result := testutil.ScanContent(t, "/app/services/runner.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-005")
}

func TestRB005_URIOpenWithParams(t *testing.T) {
	content := `def fetch_url
  data = URI.open(params[:url]).read
end`
	result := testutil.ScanContent(t, "/app/controllers/proxy_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-005")
}

func TestRB005_FileOpen_Safe(t *testing.T) {
	content := `def read_file
  data = File.open("config.yml").read
end`
	result := testutil.ScanContent(t, "/app/services/reader.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-005")
}

// ==========================================================================
// BATOU-RB-006: send/public_send with User Input
// ==========================================================================

func TestRB006_SendWithParams(t *testing.T) {
	content := `def dynamic_action
  obj.send(params[:method], params[:arg])
end`
	result := testutil.ScanContent(t, "/app/controllers/dynamic_controller.rb", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-RB-006", "BATOU-RB-013")
}

func TestRB006_PublicSendWithParams(t *testing.T) {
	content := `def call_method
  record.public_send(params[:action])
end`
	result := testutil.ScanContent(t, "/app/services/dispatcher.rb", content)
	// Overlapping rules may win dedup; either detection is valid.
	testutil.MustFindAnyRule(t, result, "BATOU-RB-006", "BATOU-RB-013")
}

func TestRB006_SendWithLiteral_Safe(t *testing.T) {
	content := `def update_field
  record.send(:update_name, new_name)
end`
	result := testutil.ScanContent(t, "/app/services/updater.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-006")
}

// ==========================================================================
// BATOU-RB-007: Regex Injection
// ==========================================================================

func TestRB007_RegexpNewWithParams(t *testing.T) {
	content := `def search
  pattern = Regexp.new(params[:query])
  results = items.select { |i| i.name =~ pattern }
end`
	result := testutil.ScanContent(t, "/app/controllers/search_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-007")
}

func TestRB007_RegexpEscape_Safe(t *testing.T) {
	content := `def search
  pattern = Regexp.new(Regexp.escape(params[:query]))
  results = items.select { |i| i.name =~ pattern }
end`
	result := testutil.ScanContent(t, "/app/controllers/search_controller.rb", content)
	// Regexp.escape sanitizes the input, so this is safe
	testutil.MustNotFindRule(t, result, "BATOU-RB-007")
}

// ==========================================================================
// BATOU-RB-008: Insecure SSL
// ==========================================================================

func TestRB008_SSLVerifyNone(t *testing.T) {
	content := `require 'net/http'
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
response = http.get(uri.path)`
	result := testutil.ScanContent(t, "/app/services/http_client.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-008")
}

func TestRB008_VerifyPeerFalse(t *testing.T) {
	content := `RestClient::Resource.new(
  url,
  verify_peer: false
)`
	result := testutil.ScanContent(t, "/app/services/api_client.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-008")
}

func TestRB008_SSLVerifyPeer_Safe(t *testing.T) {
	content := `require 'net/http'
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
http.verify_mode = OpenSSL::SSL::VERIFY_PEER
response = http.get(uri.path)`
	result := testutil.ScanContent(t, "/app/services/http_client.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-008")
}

// ==========================================================================
// BATOU-RB-009: Marshal.load
// ==========================================================================

func TestRB009_MarshalLoad(t *testing.T) {
	content := `def deserialize(data)
  obj = Marshal.load(data)
  process(obj)
end`
	result := testutil.ScanContent(t, "/app/services/cache.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-009")
}

func TestRB009_MarshalRestore(t *testing.T) {
	content := `def restore_session(blob)
  session = Marshal.restore(blob)
end`
	result := testutil.ScanContent(t, "/app/services/session_store.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-009")
}

func TestRB009_JSONParse_Safe(t *testing.T) {
	content := `def deserialize(data)
  obj = JSON.parse(data)
  process(obj)
end`
	result := testutil.ScanContent(t, "/app/services/cache.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-009")
}

// ==========================================================================
// BATOU-RB-010: Mass Assignment
// ==========================================================================

func TestRB010_UpdateAttributesWithParams(t *testing.T) {
	content := `def update
  @user.update_attributes(params[:user])
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-010")
}

func TestRB010_CreateWithRawParams(t *testing.T) {
	content := `def create
  User.create(params[:user])
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-010")
}

func TestRB010_AttrAccessible(t *testing.T) {
	content := `class User < ActiveRecord::Base
  attr_accessible :name, :email
end`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-010")
}

func TestRB010_StrongParams_Safe(t *testing.T) {
	content := `def create
  @user = User.new(user_params)
end

private

def user_params
  params.require(:user).permit(:name, :email)
end`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-010")
}

// ==========================================================================
// BATOU-RB-011: Open Redirect
// ==========================================================================

func TestRB011_RedirectToParams(t *testing.T) {
	content := `def login
  authenticate(params[:email], params[:password])
  redirect_to params[:return_url]
end`
	result := testutil.ScanContent(t, "/app/controllers/sessions_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-011")
}

func TestRB011_RedirectToReferer(t *testing.T) {
	content := `def back
  redirect_to request.referer
end`
	result := testutil.ScanContent(t, "/app/controllers/application_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-011")
}

func TestRB011_RedirectToNamedRoute_Safe(t *testing.T) {
	content := `def login
  authenticate(params[:email], params[:password])
  redirect_to root_path
end`
	result := testutil.ScanContent(t, "/app/controllers/sessions_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-011")
}

// ==========================================================================
// BATOU-RB-012: Cookie Security
// ==========================================================================

func TestRB012_CookieFromParams(t *testing.T) {
	content := `def set_pref
  cookies[:theme] = params[:theme]
end`
	result := testutil.ScanContent(t, "/app/controllers/prefs_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-RB-012")
}

func TestRB012_CookieWithFlags_Safe(t *testing.T) {
	content := `def set_pref
  cookies[:theme] = { value: "dark", httponly: true, secure: true, same_site: :lax }
end`
	result := testutil.ScanContent(t, "/app/controllers/prefs_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-RB-012")
}
