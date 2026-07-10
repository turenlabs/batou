require 'open-uri'
class FeedController < ApplicationController
  def import
    feed_url = params[:feed_url]
    content = URI.open(feed_url).read
    render xml: content
  end
end
