# RailsGoat Session Fixation
# Expected: GTSS-AUTH-004 (Session Fixation)
# CWE-384, OWASP A07
class SessionsController < ApplicationController

  # VULNERABLE: RailsGoat session fixation - not resetting session on login
  def create
    user = User.find_by(email: params[:email])
    if user && user.authenticate(params[:password])
      # VULNERABLE: session not reset before setting user_id
      session[:user_id] = user.id
      session[:admin] = user.admin?
      redirect_to dashboard_path
    else
      flash[:error] = "Invalid credentials"
      render :new
    end
  end

  # VULNERABLE: no session reset on logout
  def destroy
    session[:user_id] = nil
    redirect_to root_path
  end
end
