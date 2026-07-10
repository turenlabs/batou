class PagesController < ApplicationController
  def render_html
    html = params[:html]
    render html: html.html_safe
  end
end
