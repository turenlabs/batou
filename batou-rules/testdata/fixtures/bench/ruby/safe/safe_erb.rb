require 'sinatra'
require 'cgi'
require 'json'
require 'pathname'

UPLOAD_DIR = Pathname.new('/var/www/uploads')

# SAFE: ERB with h() helper (html_escape) for output escaping
get '/search' do
  @query = CGI.escapeHTML(params[:q].to_s)
  erb :search
end

# SAFE: JSON response (no HTML rendering)
get '/api/users' do
  name = params[:name]
  content_type :json
  { name: name, status: 'active' }.to_json
end

# SAFE: File path validated with realpath + start_with?
get '/download' do
  name = params[:file]
  resolved = File.realpath(File.join(UPLOAD_DIR.to_s, name))

  unless resolved.start_with?(UPLOAD_DIR.to_s)
    halt 403, { error: 'Access denied' }.to_json
  end

  send_file resolved
end

# SAFE: Allowlist of permitted templates
get '/page/:name' do
  allowed = %w[about contact faq terms]
  template = params[:name]

  unless allowed.include?(template)
    halt 404
  end

  erb template.to_sym
end

# SAFE: File.basename strips directory traversal
get '/serve' do
  raw_name = params[:name]
  safe_name = File.basename(raw_name)
  path = File.join(UPLOAD_DIR.to_s, safe_name)
  send_file path
end
