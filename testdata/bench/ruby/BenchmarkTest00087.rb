require 'net/http'
class ApiController < ApplicationController
  def proxy
    endpoint = params[:endpoint]
    uri = URI.parse(endpoint)
    response = Net::HTTP.get_response(uri)
    render json: response.body
  end
end
