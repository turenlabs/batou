class VideoController < ApplicationController
  def transcode
    input = params[:input_file]
    system("ffmpeg -i #{input} output.mp4")
    render plain: "transcoded"
  end
end
