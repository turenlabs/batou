class AccountController < ApplicationController
  def confirm
    confirm_email(params[:token])
    redirect_to login_path
  end
end
