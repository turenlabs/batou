class VideoController < ApplicationController
  def transcode
    input = params[:input_file]
    safe_input = File.basename(input)
    system("ffmpeg", "-i", safe_input, "output.mp4")
    render plain: "transcoded"
  end
end
