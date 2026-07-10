class TemplatesController < ApplicationController
  def preview
    name = params[:name]
    content = File.readlines("templates/#{name}").join
    render html: content.html_safe
  end
end
