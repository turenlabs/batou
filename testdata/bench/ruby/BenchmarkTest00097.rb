require 'net/http'
class MetadataController < ApplicationController
  def fetch
    service_url = params[:service_url]
    uri = URI.parse(service_url)
    response = Net::HTTP.get(uri)
    render json: JSON.parse(response)
  end
end
