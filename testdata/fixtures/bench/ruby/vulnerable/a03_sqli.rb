# Source: OWASP Rails Goat - SQL injection in ActiveRecord
# Expected: GTSS-INJ-001 (SQL Injection via string interpolation)
# OWASP: A03:2021 - Injection (SQL Injection)

class UsersController < ApplicationController
  def search
    query = params[:q]
    @users = User.where("username LIKE '%#{query}%' OR email LIKE '%#{query}%'")
    render json: @users
  end

  def show
    user_id = params[:id]
    @user = User.find_by_sql("SELECT * FROM users WHERE id = #{user_id}").first
    if @user
      render json: @user
    else
      render json: { error: 'Not found' }, status: 404
    end
  end

  def authenticate
    username = params[:username]
    password = params[:password]
    sql = "SELECT * FROM users WHERE username = '#{username}' AND password_digest = '#{password}'"
    user = ActiveRecord::Base.connection.execute(sql).first
    if user
      session[:user_id] = user['id']
      redirect_to dashboard_path
    else
      flash[:error] = 'Invalid credentials'
      redirect_to login_path
    end
  end
end
