class UsersController < ApplicationController
  def search
    query = params[:query]
    @users = User.where(name: query)
    render json: @users
  end
end
