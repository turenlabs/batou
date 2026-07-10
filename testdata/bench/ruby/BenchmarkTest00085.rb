require 'net/http'
class ImageController < ApplicationController
  def fetch
    image_url = params[:image_url]
    uri = URI.parse(image_url)
    http = Net::HTTP.new(uri.host, uri.port)
    response = http.get(uri.path)
    send_data response.body, type: "image/png"
  end
end
