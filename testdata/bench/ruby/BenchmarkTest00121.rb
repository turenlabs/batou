class AuthController < ApplicationController
  def callback
    redirect_to params[:return_url]
  end
end
