# Safe: Proper strong parameters usage
# Expected: No findings for mass assignment

class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    if @user.save
      redirect_to @user
    else
      render :new
    end
  end

  def update
    @user = User.find(params[:id])
    if @user.update(user_params)
      redirect_to @user
    else
      render :edit
    end
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :phone)
  end
end

class AccountsController < ApplicationController
  def create
    @account = Account.new(account_params)
    @account.save!
    redirect_to @account
  end

  private

  def account_params
    params.require(:account).permit(:name, :description, :plan)
  end
end
