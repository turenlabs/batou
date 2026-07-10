require 'net/http'
class PreviewController < ApplicationController
  def page
    page_url = params[:page_url]
    uri = URI.parse(page_url)
    http = Net::HTTP.new(uri.host, uri.port)
    response = http.request(Net::HTTP::Get.new(uri))
    render html: response.body.html_safe
  end
end
