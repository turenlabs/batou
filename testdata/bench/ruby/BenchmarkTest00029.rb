class NotificationsController < ApplicationController
  def alert
    msg = params[:message]
    render html: raw(params[:message])
  end
end
