require 'net/http'
class PreviewController < ApplicationController
  def page
    slug = params[:slug].gsub(/[^a-z0-9-]/, "")
    uri = URI.parse("https://www.example.com/pages/#{slug}")
    response = Net::HTTP.get(uri)
    render html: response
  end
end
