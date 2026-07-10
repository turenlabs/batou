class SsoController < ApplicationController
  def callback
    token = params[:token]
    verify_sso(token)
    redirect_to params[:continue]
  end
end
