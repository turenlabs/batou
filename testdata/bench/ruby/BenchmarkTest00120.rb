class SettingsController < ApplicationController
  def load
    settings_json = params[:settings]
    settings = JSON.parse(settings_json)
    render json: settings
  end
end
