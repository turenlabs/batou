class InviteController < ApplicationController
  def accept
    accept_invite(params[:token])
    redirect_to params[:redirect_to]
  end
end
