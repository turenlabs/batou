class PostsController < ApplicationController
  def index
    allowed_sorts = %w[asc desc]
    order = allowed_sorts.include?(params[:sort]) ? params[:sort] : "asc"
    @posts = Post.order(created_at: order.to_sym)
    render json: @posts
  end
end
