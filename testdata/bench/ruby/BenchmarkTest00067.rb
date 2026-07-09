class AvatarsController < ApplicationController
  def show
    user_file = params[:avatar]
    send_data File.binread("avatars/#{user_file}")
  end
end
