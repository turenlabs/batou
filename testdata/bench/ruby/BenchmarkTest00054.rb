class ImageController < ApplicationController
  def resize
    width = params[:width].to_i
    height = params[:height].to_i
    return head(:bad_request) unless width.between?(1, 4096) && height.between?(1, 4096)
    system("mogrify", "-resize", "#{width}x#{height}", "uploaded.jpg")
    render plain: "resized"
  end
end
