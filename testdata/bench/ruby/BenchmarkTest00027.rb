class CommentsController < ApplicationController
  def show
    @comment = params[:body]
    output = "<p>#{@comment}</p>".html_safe
    render html: output
  end
end
