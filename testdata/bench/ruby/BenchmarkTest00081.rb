require 'net/http'
class WebhookController < ApplicationController
  def fetch
    url = params[:url]
    uri = URI.parse(url)
    response = Net::HTTP.get(uri)
    render plain: response
  end
end
