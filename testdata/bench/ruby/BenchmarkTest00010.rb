class AdminController < ApplicationController
  def lookup
    email = params[:email]
    @user = User.where(email: email)
    render json: @user
  end
end
