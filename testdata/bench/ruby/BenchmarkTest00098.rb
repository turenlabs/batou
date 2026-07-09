require 'net/http'
class MetadataController < ApplicationController
  def fetch
    service = params[:service]
    allowed = { "auth" => "https://auth.internal/meta", "api" => "https://api.internal/meta" }
    url = allowed[service]
    return head(:not_found) unless url
    uri = URI.parse(url)
    response = Net::HTTP.get(uri)
    render json: JSON.parse(response)
  end
end
