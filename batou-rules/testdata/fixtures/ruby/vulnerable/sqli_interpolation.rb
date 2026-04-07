# Vulnerable: SQL injection via string interpolation in ActiveRecord .where()
# Expected: GTSS-INJ-001 (SQL Injection)

class UsersController < ApplicationController
  def show
    user_id = params[:id]
    @user = User.where("id = '#{user_id}'")
    render json: @user
  end

  def search
    name = params[:name]
    @users = User.where("name LIKE '%#{name}%'")
    render json: @users
  end

  def admin_lookup
    email = params[:email]
    @admin = User.where("email = '#{email}' AND admin = true")
    render json: @admin
  end
end
