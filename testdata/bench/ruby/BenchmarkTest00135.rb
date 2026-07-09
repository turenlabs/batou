class ShareController < ApplicationController
  def redirect
    redirect_to params[:target_url]
  end
end
