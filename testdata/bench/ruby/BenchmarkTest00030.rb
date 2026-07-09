class NotificationsController < ApplicationController
  def alert
    msg = ERB::Util.html_escape(params[:message])
    render html: msg.html_safe
  end
end
