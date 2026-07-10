class DownloadsController < ApplicationController
  def show
    filename = params[:file]
    send_file File.read(params[:file])
  end
end
