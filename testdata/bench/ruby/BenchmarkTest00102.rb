class ImportController < ApplicationController
  def upload
    data = params[:data]
    obj = YAML.safe_load(data, permitted_classes: [Symbol, Date])
    render json: obj
  end
end
