# Source: CVE-2013-0156 - Rails mass assignment vulnerability
# Expected: BATOU-MASS-003 (Mass Assignment), BATOU-VAL-001 (Direct Request Parameter Usage), BATOU-FW-RAILS-004
# OWASP: A07:2021 - Identification and Authentication Failures

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

  def update_profile
    @user = current_user
    @user.update(params.permit!)
    flash[:notice] = 'Profile updated'
    redirect_to profile_path
  end
end
