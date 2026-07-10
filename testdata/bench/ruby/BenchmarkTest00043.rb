class ConvertController < ApplicationController
  def process_file
    filename = params[:filename]
    system("convert #{filename} output.png")
    render plain: "converted"
  end
end
