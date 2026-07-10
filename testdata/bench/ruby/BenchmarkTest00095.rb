require 'open-uri'
class DownloadController < ApplicationController
  def file
    remote = params[:remote_url]
    data = URI.open(remote).read
    send_data data
  end
end
