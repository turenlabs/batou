class ConfigController < ApplicationController
  def update
    yaml_data = request.body.read
    config = YAML.load(yaml_data)
    render json: config
  end
end
