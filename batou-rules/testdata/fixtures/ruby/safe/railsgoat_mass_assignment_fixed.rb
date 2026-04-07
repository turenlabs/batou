# RailsGoat Mass Assignment - Fixed with strong parameters
class UsersController < ApplicationController

  def update
    @user = User.find(params[:id])
    # SAFE: Using strong parameters with explicit permit list
    @user.update(user_params)
    redirect_to @user
  end

  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render :new
    end
  end

  private

  # SAFE: Explicit allowlist of permitted attributes
  def user_params
    params.require(:user).permit(:name, :email, :password, :password_confirmation)
  end
end
