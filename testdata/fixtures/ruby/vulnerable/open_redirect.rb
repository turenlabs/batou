# Vulnerable: Open redirect via redirect_to with user-controlled URL
# Expected: Taint sink match for ruby.rails.redirect_to (CWE-601)

class AuthController < ApplicationController
  def login
    user = User.authenticate(params[:email], params[:password])
    if user
      session[:user_id] = user.id
      redirect_to params[:return_url]
    else
      flash[:error] = "Invalid credentials"
      render :login
    end
  end

  def logout
    reset_session
    redirect_to params[:redirect]
  end

  def callback
    url = params[:url]
    redirect_to(url)
  end
end
