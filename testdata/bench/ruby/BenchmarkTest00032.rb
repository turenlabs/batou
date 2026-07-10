class WidgetsController < ApplicationController
  def embed
    code = params[:embed_code]
    @widget = content_tag(:div, code, class: 'widget')
    render html: @widget
  end
end
