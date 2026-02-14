# RailsGoat Mass Assignment
# Expected: GTSS-RB-010, GTSS-MASS-003, GTSS-FW-RAILS-004
# CWE-915, OWASP A07
class UsersController < ApplicationController

  # VULNERABLE: RailsGoat mass assignment - no strong parameters
  def update
    @user = User.find(params[:id])
    @user.update(params[:user].permit!)
    redirect_to @user
  end

  # VULNERABLE: RailsGoat mass assignment via create with permit!
  def create
    @user = User.new(params[:user].permit!)
    if @user.save
      redirect_to @user
    else
      render :new
    end
  end

  # VULNERABLE: permit! allows all attributes including admin flag
  def admin_update
    user = User.find(params[:id])
    user.update_attributes(params.permit!)
    render json: user
  end
end
