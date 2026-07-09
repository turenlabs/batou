class ConvertController < ApplicationController
  def process_file
    filename = params[:filename]
    sanitized = Shellwords.escape(filename)
    system("convert", sanitized, "output.png")
    render plain: "converted"
  end
end
