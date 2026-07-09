class TemplatesController < ApplicationController
  ALLOWED_TEMPLATES = %w[header footer sidebar].freeze
  def preview
    name = params[:name]
    return head(:bad_request) unless ALLOWED_TEMPLATES.include?(name)
    content = File.read(Rails.root.join("templates", "#{name}.html"))
    render html: content.html_safe
  end
end
