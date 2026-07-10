require 'net/http'
class CallbackController < ApplicationController
  def verify
    token = params[:token]
    uri = URI.parse("https://verify.example.com/callback?token=#{CGI.escape(token)}")
    response = Net::HTTP.get_response(uri)
    render json: { verified: response.code == "200" }
  end
end
