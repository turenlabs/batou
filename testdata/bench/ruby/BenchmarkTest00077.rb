class ImagesController < ApplicationController
  def show
    image = params[:image]
    File.open("public/images/#{image}") do |f|
      send_data f.read, type: "image/png"
    end
  end
end
