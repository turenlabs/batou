class LoginController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    if user
      sign_in(user)
      redirect_to root_path
    else
      render :new
    end
  end
end
