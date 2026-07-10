require 'net/http'
class HealthController < ApplicationController
  def check
    target = params[:target]
    uri = URI.parse(target)
    response = Net::HTTP.get(uri)
    render json: { status: response.length > 0 ? "up" : "down" }
  end
end
