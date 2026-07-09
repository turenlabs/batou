require 'net/http'
class ApiController < ApplicationController
  def proxy
    resource = params[:resource]
    allowed = %w[users posts comments]
    return head(:bad_request) unless allowed.include?(resource)
    uri = URI.parse("https://api.example.com/v1/#{resource}")
    response = Net::HTTP.get_response(uri)
    render json: response.body
  end
end
