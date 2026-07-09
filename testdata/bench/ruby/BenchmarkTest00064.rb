class AssetsController < ApplicationController
  def serve
    path = params[:path]
    base = Rails.root.join("uploads").to_s
    full = File.expand_path(path, base)
    return head(:forbidden) unless full.start_with?(base)
    render plain: File.read(full)
  end
end
