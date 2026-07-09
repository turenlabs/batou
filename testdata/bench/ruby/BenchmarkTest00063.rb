class AssetsController < ApplicationController
  def serve
    path = params[:path]
    content = File.read("#{Rails.root}/uploads/#{path}")
    render plain: content
  end
end
