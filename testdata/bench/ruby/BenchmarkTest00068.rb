class AvatarsController < ApplicationController
  def show
    user_file = File.basename(params[:avatar])
    path = Rails.root.join("avatars", user_file)
    return head(:not_found) unless File.exist?(path)
    send_data File.binread(path)
  end
end
