require 'open-uri'
class ProxyController < ApplicationController
  def get
    url = params[:url]
    data = URI.open(params[:url]).read
    render plain: data
  end
end
