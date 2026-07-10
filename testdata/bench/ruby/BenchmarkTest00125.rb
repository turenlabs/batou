class OAuthController < ApplicationController
  def callback
    redirect_to params[:next]
  end
end
