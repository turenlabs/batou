class PagesController < ApplicationController
  def render_html
    html = params[:html]
    sanitized = ActionController::Base.helpers.sanitize(html)
    render html: sanitized.html_safe
  end
end
