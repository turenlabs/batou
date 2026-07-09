class SearchController < ApplicationController
  def results
    query = params[:q]
    @message = "Results for: #{ERB::Util.html_escape(query)}"
    render html: @message.html_safe
  end
end
