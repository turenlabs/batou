require 'net/http'
class DownloadController < ApplicationController
  def file
    id = params[:id].to_i
    attachment = Attachment.find(id)
    uri = URI.parse(attachment.internal_url)
    response = Net::HTTP.get(uri)
    send_data response
  end
end
