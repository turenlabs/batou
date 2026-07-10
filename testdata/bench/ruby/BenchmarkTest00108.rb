class DataController < ApplicationController
  def import
    payload = params[:payload]
    obj = JSON.parse(payload)
    render json: obj
  end
end
