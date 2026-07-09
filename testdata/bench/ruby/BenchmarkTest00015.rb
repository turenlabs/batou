class CommentsController < ApplicationController
  def index
    post_id = params[:post_id]
    @comments = Comment.where("post_id = #{post_id} AND approved = true")
    render json: @comments
  end
end
