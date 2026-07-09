class ImagesController < ApplicationController
  def show
    image = File.basename(params[:image])
    path = Rails.root.join("public", "images", image)
    return head(:not_found) unless File.exist?(path)
    send_data File.read(path), type: "image/png"
  end
end
