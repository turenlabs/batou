class AttachmentsController < ApplicationController
  def download
    file = File.basename(params[:file])
    base = Rails.root.join("attachments").to_s
    full = File.expand_path(file, base)
    return head(:forbidden) unless full.start_with?(base)
    send_data File.read(full)
  end
end
