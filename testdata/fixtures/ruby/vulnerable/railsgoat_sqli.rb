# RailsGoat SQL Injection
# Expected: GTSS-INJ-001, GTSS-FW-RAILS-006
# CWE-89, OWASP A03
class AnalyticsController < ApplicationController

  # VULNERABLE: RailsGoat SQL injection via string interpolation
  def search
    query = params[:query]
    @results = User.where("name LIKE '%#{query}%'")
    render :search
  end

  # VULNERABLE: RailsGoat SQL injection via find_by_sql
  def custom_query
    field = params[:field]
    value = params[:value]
    @users = User.find_by_sql("SELECT * FROM users WHERE #{field} = '#{value}'")
    render json: @users
  end

  # VULNERABLE: order clause injection
  def sorted
    order = params[:order]
    @users = User.order(order)
    render json: @users
  end
end
