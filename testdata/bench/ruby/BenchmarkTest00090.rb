require 'net/http'
class FeedController < ApplicationController
  FEED_URLS = {
    "news" => "https://feeds.example.com/news",
    "blog" => "https://feeds.example.com/blog"
  }.freeze
  def import
    key = params[:feed]
    url = FEED_URLS[key]
    return head(:not_found) unless url
    uri = URI.parse(url)
    response = Net::HTTP.get(uri)
    render xml: response
  end
end
