class SessionController < ApplicationController
  def restore
    cookie = cookies.signed[:session_data]
    render json: cookie
  end
end
