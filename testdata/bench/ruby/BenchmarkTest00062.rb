class DownloadsController < ApplicationController
  def show
    filename = params[:file]
    safe_path = File.expand_path(filename, Rails.root.join("uploads"))
    return head(:forbidden) unless safe_path.start_with?(Rails.root.join("uploads").to_s)
    send_file safe_path
  end
end
