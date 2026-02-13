# GTSS-RB-011: Open Redirect

class SessionsController < ApplicationController
  def login
    # Vulnerable: redirect_to with user-controlled URL
    redirect_to params[:return_url]
  end

  def logout
    # Vulnerable: redirect_to with interpolated user input
    redirect_to "#{params[:next]}"
  end
end
