class LoginController < ApplicationController
  def create
    user = User.authenticate(params[:email], params[:password])
    if user
      sign_in(user)
      redirect_to params[:redirect]
    else
      render :new
    end
  end
end
