class SessionController < ApplicationController
  def restore
    cookie = cookies[:session_data]
    session = Marshal.load(Base64.decode64(cookie))
    render json: session
  end
end
