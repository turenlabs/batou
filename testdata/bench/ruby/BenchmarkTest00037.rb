class SearchController < ApplicationController
  def results
    query = params[:q]
    @message = "Results for: #{query}".html_safe
    render html: @message
  end
end
