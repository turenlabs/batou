# RailsGoat SQL Injection - Fixed with parameterized queries
class AnalyticsController < ApplicationController

  def search
    query = params[:query]
    # SAFE: Using ActiveRecord parameterized where clause
    @results = User.where("name LIKE ?", "%#{query}%")
    render :search
  end

  def custom_query
    value = params[:value]
    # SAFE: Using find_by with hash syntax
    @users = User.where(email: value)
    render json: @users
  end
end
