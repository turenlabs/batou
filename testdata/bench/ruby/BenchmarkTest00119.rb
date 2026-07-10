class SettingsController < ApplicationController
  def load
    yaml = params[:settings_yaml]
    settings = YAML.load(yaml)
    render json: settings
  end
end
