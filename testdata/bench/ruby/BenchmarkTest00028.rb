class CommentsController < ApplicationController
  def show
    @comment = params[:body]
    render plain: @comment
  end
end
