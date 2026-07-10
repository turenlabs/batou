class WidgetsController < ApplicationController
  def embed
    code = params[:embed_code]
    @widget = "<div class='widget'>#{code}</div>".html_safe
    render html: @widget
  end
end
