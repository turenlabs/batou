class InviteController < ApplicationController
  def accept
    accept_invite(params[:token])
    redirect_to welcome_path
  end
end
