class ImageController < ApplicationController
  def resize
    size = params[:size]
    system("mogrify -resize #{size} uploaded.jpg")
    render plain: "resized"
  end
end
