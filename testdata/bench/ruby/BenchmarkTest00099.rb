require 'net/http'
class CallbackController < ApplicationController
  def verify
    callback_url = params[:callback_url]
    uri = URI.parse(callback_url)
    response = Net::HTTP.get_response(uri)
    render json: { verified: response.code == "200" }
  end
end
