class CommentsController < ApplicationController
  def index
    post_id = params[:post_id].to_i
    @comments = Comment.where(post_id: post_id, approved: true)
    render json: @comments
  end
end
