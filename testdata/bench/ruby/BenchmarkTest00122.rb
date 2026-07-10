class AuthController < ApplicationController
  def callback
    return_url = params[:return_url]
    if return_url&.start_with?("/")
      redirect_to return_url
    else
      redirect_to root_path
    end
  end
end
