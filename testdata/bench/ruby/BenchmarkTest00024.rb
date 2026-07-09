class MessagesController < ApplicationController
  def preview
    content = params[:content]
    render json: { content: content }
  end
end
