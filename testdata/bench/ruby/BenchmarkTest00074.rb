class ExportsController < ApplicationController
  def download
    filename = File.basename(params[:filename])
    path = Rails.root.join("exports", filename)
    return head(:not_found) unless File.exist?(path)
    send_file path.to_s
  end
end
