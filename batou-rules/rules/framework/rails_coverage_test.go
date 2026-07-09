package framework

import (
	"testing"

	"github.com/turenlabs/batou-rules/testutil"
)

// ==========================================================================
// BATOU-FW-RAILS-013: ActiveRecord aggregate/projection SQL injection
// ==========================================================================

func TestRails013_PluckInterp_Vulnerable(t *testing.T) {
	content := `class ReportsController < ApplicationController
  def index
    @vals = Order.pluck("#{params[:col]}")
  end
end`
	result := testutil.ScanContent(t, "/app/controllers/reports_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_ReorderParams_Vulnerable(t *testing.T) {
	content := `@posts = Post.all.reorder(params[:sort])`
	result := testutil.ScanContent(t, "/app/controllers/posts_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_CalculateInterp_Vulnerable(t *testing.T) {
	content := `total = Invoice.calculate(:sum, "amount + #{params[:bonus]}")`
	result := testutil.ScanContent(t, "/app/models/invoice.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_UpdateAllInterp_Vulnerable(t *testing.T) {
	content := `User.where(id: ids).update_all("role = '#{params[:role]}'")`
	result := testutil.ScanContent(t, "/app/controllers/admin_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_ExistsInterp_Vulnerable(t *testing.T) {
	content := `User.exists?("name = '#{params[:name]}'")`
	result := testutil.ScanContent(t, "/app/controllers/users_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_PluckSymbol_Safe(t *testing.T) {
	content := `ids = User.pluck(:id)
names = User.pluck(:name, :email)
total = Order.sum(:amount)
avg = Order.average(:price)`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_UpdateAllHash_Safe(t *testing.T) {
	content := `User.where(active: true).update_all(role: "member")`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_I18nExists_Safe(t *testing.T) {
	// I18n.exists?, File.exists? etc. take a key/path, not a SQL condition.
	content := `return true if I18n.exists?("js.#{page_name}")
serve if File.exists?("public/#{name}")`
	result := testutil.ScanContent(t, "/app/controllers/static_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-013")
}

func TestRails013_ConstantInterp_Safe(t *testing.T) {
	// Interpolating only framework/model constants (table/column metadata) into a
	// pluck/order column is a fixed identifier, not user input — must stay clean.
	// This is the GitLab false-positive shape: pluck("#{Group.table_name}.#{Group.primary_key}").
	content := `ids = relation.pluck("#{Group.table_name}.#{Group.primary_key}")
sorted = Post.reorder("#{Post.table_name}.created_at")
total = Order.calculate(:sum, "#{Order::AMOUNT_COL}")`
	result := testutil.ScanContent(t, "/app/lib/search_results.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-013")
}

// ==========================================================================
// BATOU-FW-RAILS-014: validates :format with ^...$ anchors
// ==========================================================================

func TestRails014_LineAnchors_Vulnerable(t *testing.T) {
	content := `class User < ApplicationRecord
  validates :username, format: { with: /^[a-zA-Z0-9]+$/ }
end`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-014")
}

func TestRails014_ValidatesFormatOf_Vulnerable(t *testing.T) {
	content := `validates_format_of :email, format: /^.+@.+$/`
	result := testutil.ScanContent(t, "/app/models/account.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-014")
}

func TestRails014_StringAnchors_Safe(t *testing.T) {
	content := `class User < ApplicationRecord
  validates :username, format: { with: /\A[a-zA-Z0-9]+\z/ }
end`
	result := testutil.ScanContent(t, "/app/models/user.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-014")
}

// ==========================================================================
// BATOU-FW-RAILS-015: link_to target _blank without rel noopener
// ==========================================================================

func TestRails015_BlankNoRel_Vulnerable(t *testing.T) {
	content := `<%= link_to "External", @url, target: "_blank" %>`
	result := testutil.ScanContent(t, "/app/views/posts/show.html.erb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-015")
}

func TestRails015_BlankWithNoopener_Safe(t *testing.T) {
	content := `<%= link_to "External", @url, target: "_blank", rel: "noopener noreferrer" %>`
	result := testutil.ScanContent(t, "/app/views/posts/show.html.erb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-015")
}

// ==========================================================================
// BATOU-FW-RAILS-016: http_basic_authenticate_with hardcoded creds
// ==========================================================================

func TestRails016_LiteralCreds_Vulnerable(t *testing.T) {
	content := `class AdminController < ApplicationController
  http_basic_authenticate_with name: "admin", password: "s3cret"
end`
	result := testutil.ScanContent(t, "/app/controllers/admin_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-016")
}

func TestRails016_EnvCreds_Safe(t *testing.T) {
	content := `http_basic_authenticate_with name: ENV["ADMIN_USER"], password: ENV["ADMIN_PASS"]`
	result := testutil.ScanContent(t, "/app/controllers/admin_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-016")
}

// ==========================================================================
// BATOU-FW-RAILS-017: verb-permissive route
// ==========================================================================

func TestRails017_ViaAll_Vulnerable(t *testing.T) {
	content := `Rails.application.routes.draw do
  match 'transfer', to: 'payments#transfer', via: :all
end`
	result := testutil.ScanContent(t, "/config/routes.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-017")
}

func TestRails017_ViaAllHashRocket_Vulnerable(t *testing.T) {
	content := `Rails.application.routes.draw do
  match "/webhook/*path" => "webhooks#receive", :via => :all
end`
	result := testutil.ScanContent(t, "/config/routes.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-017")
}

func TestRails017_NoVia_Safe(t *testing.T) {
	// A bare match without via: :all is not flagged (too low-signal / FP-prone on
	// multi-line match blocks); only via: :all is.
	content := `Rails.application.routes.draw do
  match 'profile', to: 'users#show', via: :get
end`
	result := testutil.ScanContent(t, "/config/routes.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-017")
}

func TestRails017_ViaPost_Safe(t *testing.T) {
	content := `Rails.application.routes.draw do
  match 'transfer', to: 'payments#transfer', via: :post
end`
	result := testutil.ScanContent(t, "/config/routes.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-017")
}

// ==========================================================================
// BATOU-FW-RAILS-018: escape_html_entities_in_json = false
// ==========================================================================

func TestRails018_JSONEscapeOff_Vulnerable(t *testing.T) {
	content := `ActiveSupport.escape_html_entities_in_json = false`
	result := testutil.ScanContent(t, "/config/initializers/json.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-018")
}

func TestRails018_JSONEscapeOn_Safe(t *testing.T) {
	content := `ActiveSupport.escape_html_entities_in_json = true`
	result := testutil.ScanContent(t, "/config/initializers/json.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-018")
}

// ==========================================================================
// BATOU-FW-RAILS-019: whitelist_attributes = false
// ==========================================================================

func TestRails019_WhitelistOff_Vulnerable(t *testing.T) {
	content := `config.active_record.whitelist_attributes = false`
	result := testutil.ScanContent(t, "/config/application.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-019")
}

func TestRails019_WhitelistOn_Safe(t *testing.T) {
	content := `config.active_record.whitelist_attributes = true`
	result := testutil.ScanContent(t, "/config/application.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-019")
}

// ==========================================================================
// BATOU-FW-RAILS-020: dynamic render path (LFI)
// ==========================================================================

func TestRails020_RenderParams_Vulnerable(t *testing.T) {
	content := `class ReportsController < ApplicationController
  def show
    render params[:template]
  end
end`
	result := testutil.ScanContent(t, "/app/controllers/reports_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-020")
}

func TestRails020_RenderInterp_Vulnerable(t *testing.T) {
	content := `render "reports/#{params[:id]}"`
	result := testutil.ScanContent(t, "/app/controllers/reports_controller.rb", content)
	testutil.MustFindRule(t, result, "BATOU-FW-RAILS-020")
}

func TestRails020_RenderStaticPartial_Safe(t *testing.T) {
	content := `render "shared/header"
render partial: "posts/post", collection: @posts
render json: @user
render template: "static/about"`
	result := testutil.ScanContent(t, "/app/controllers/pages_controller.rb", content)
	testutil.MustNotFindRule(t, result, "BATOU-FW-RAILS-020")
}
