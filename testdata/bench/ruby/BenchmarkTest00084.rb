require 'net/http'
class ProxyController < ApplicationController
  def get
    path = params[:path]
    uri = URI.parse("https://api.internal.example.com/#{path}")
    response = Net::HTTP.get(uri)
    render plain: response
  end
end
