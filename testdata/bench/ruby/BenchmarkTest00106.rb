class ConfigController < ApplicationController
  def update
    json_data = request.body.read
    config = JSON.parse(json_data)
    render json: config
  end
end
