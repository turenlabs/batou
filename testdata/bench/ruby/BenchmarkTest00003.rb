class PostsController < ApplicationController
  def index
    order = params[:sort]
    @posts = Post.order("created_at #{order}")
    render json: @posts
  end
end
