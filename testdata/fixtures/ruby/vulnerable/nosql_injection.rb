class UsersController < ApplicationController
  # VULNERABLE: Mongoid query with unsanitized params
  def show
    user = User.where(params[:filter]).first
    render json: user
  end

  # VULNERABLE: $where with Ruby string interpolation
  def search
    term = params[:q]
    users = User.collection.find("$where" => "this.name == '#{term}'")
    render json: users.to_a
  end
end
