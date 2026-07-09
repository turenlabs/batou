class SessionsController < ApplicationController
  def destroy
    sign_out
    redirect_to params[:return_to]
  end
end
