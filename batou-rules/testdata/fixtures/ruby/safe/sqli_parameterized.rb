# Safe: Parameterized SQL queries in ActiveRecord
# Expected: No findings for GTSS-INJ-001

class UsersController < ApplicationController
  def show
    @user = User.where(id: params[:id])
    render json: @user
  end

  def search
    name = params[:name]
    @users = User.where("name LIKE ?", "%#{name}%")
    render json: @users
  end

  def admin_lookup
    email = params[:email]
    @admin = User.where("email = ? AND admin = ?", email, true)
    render json: @admin
  end

  def find_by_attrs
    @user = User.find_by(email: params[:email], active: true)
    render json: @user
  end

  def complex_query
    @results = User.where(role: params[:role])
                   .where("created_at > ?", 1.week.ago)
                   .order(:name)
    render json: @results
  end
end
