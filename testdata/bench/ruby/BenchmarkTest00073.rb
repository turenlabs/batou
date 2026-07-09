class ExportsController < ApplicationController
  def download
    filename = params[:filename]
    path = "exports/#{filename}"
    send_file path
  end
end
