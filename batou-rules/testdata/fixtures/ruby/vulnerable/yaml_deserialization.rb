# Vulnerable: Unsafe YAML deserialization with user input
# Expected: Taint sink match for ruby.yaml.load (CWE-502)

require 'yaml'

class ConfigController < ApplicationController
  def upload
    yaml_content = params[:config]
    @config = YAML.load(yaml_content)
    render json: @config
  end

  def import_settings
    file_content = request.body.read
    @settings = YAML.load(file_content)
    render json: { status: "ok", settings: @settings }
  end

  def parse_webhook
    payload = request.raw_post
    @data = YAML.load(payload)
    process_webhook(@data)
    head :ok
  end
end
