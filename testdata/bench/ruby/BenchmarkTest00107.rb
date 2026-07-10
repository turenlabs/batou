class DataController < ApplicationController
  def import
    payload = params[:payload]
    obj = Marshal.load(payload)
    render json: obj
  end
end
