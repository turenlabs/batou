class UsersController < ApplicationController
  def search
    query = params[:query]
    @users = User.where("name LIKE '%#{query}%'")
    render json: @users
  end
end
