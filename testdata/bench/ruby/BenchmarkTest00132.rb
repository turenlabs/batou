class SsoController < ApplicationController
  def callback
    token = params[:token]
    verify_sso(token)
    redirect_to dashboard_path
  end
end
