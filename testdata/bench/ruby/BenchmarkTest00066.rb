class DocsController < ApplicationController
  def show
    doc = File.basename(params[:doc])
    path = Rails.root.join("docs", doc)
    return head(:not_found) unless File.exist?(path)
    render plain: File.read(path)
  end
end
