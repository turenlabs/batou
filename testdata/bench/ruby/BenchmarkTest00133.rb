class AccountController < ApplicationController
  def confirm
    confirm_email(params[:token])
    redirect_to params[:destination]
  end
end
