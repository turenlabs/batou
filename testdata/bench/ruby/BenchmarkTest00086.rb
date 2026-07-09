require 'net/http'
class ImageController < ApplicationController
  ALLOWED_DOMAINS = %w[cdn.example.com images.example.com].freeze
  def fetch
    image_url = params[:image_url]
    uri = URI.parse(image_url)
    return head(:forbidden) unless ALLOWED_DOMAINS.include?(uri.host)
    return head(:forbidden) unless %w[http https].include?(uri.scheme)
    response = Net::HTTP.get(uri)
    send_data response, type: "image/png"
  end
end
