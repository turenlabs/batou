class AttachmentsController < ApplicationController
  def download
    file = params[:file]
    File.open("#{Rails.root}/attachments/#{file}") do |f|
      send_data f.read
    end
  end
end
