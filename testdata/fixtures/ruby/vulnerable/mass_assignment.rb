# Vulnerable: Mass assignment / missing strong parameters
# Expected: Pattern detection for mass assignment without permit

class UsersController < ApplicationController
  def create
    @user = User.new(params[:user])
    if @user.save
      redirect_to @user
    else
      render :new
    end
  end

  def update
    @user = User.find(params[:id])
    @user.update_attributes(params[:user])
    redirect_to @user
  end

  def register
    @account = Account.create(params.permit!)
    redirect_to dashboard_path
  end
end
