class MessagesController < ApplicationController
  def preview
    content = params[:content]
    render html: raw(params[:content])
  end
end
