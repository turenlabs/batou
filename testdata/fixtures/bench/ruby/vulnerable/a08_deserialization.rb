# Source: CWE-502 - Unsafe deserialization in Ruby via YAML/Marshal
# Expected: GTSS-GEN-002 (Unsafe Deserialization - YAML.load/Marshal.load)
# OWASP: A08:2021 - Software and Data Integrity Failures

require 'yaml'
require 'base64'

class SessionController < ApplicationController
  def restore
    session_data = params[:session]
    decoded = Base64.decode64(session_data)
    data = YAML.load(decoded)
    session[:user] = data[:user]
    session[:role] = data[:role]
    redirect_to dashboard_path
  end

  def import_config
    config_yaml = request.body.read
    config = YAML.load(config_yaml)
    Setting.update_all_from(config)
    render json: { status: 'imported', keys: config.keys }
  end

  def load_cache
    key = params[:key]
    raw = Rails.cache.read(key)
    obj = Marshal.load(raw) if raw
    render json: obj || { error: 'not found' }
  end
end
