class ImportController < ApplicationController
  def upload
    data = params[:data]
    obj = YAML.load(data)
    render json: obj
  end
end
