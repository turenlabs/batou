# Vulnerable: SQL injection via find_by_sql with string interpolation
# Expected: GTSS-INJ-001 (SQL Injection)

class AccountsController < ApplicationController
  def index
    sort_col = params[:sort]
    @accounts = Account.find_by_sql("SELECT * FROM accounts ORDER BY #{sort_col}")
    render json: @accounts
  end

  def balance
    account_id = params[:account_id]
    @balance = Account.find_by_sql("SELECT balance FROM accounts WHERE id = '#{account_id}'")
    render json: @balance
  end

  def transactions
    user_id = params[:user_id]
    @txns = ActiveRecord::Base.connection.execute(
      "SELECT * FROM transactions WHERE user_id = #{user_id}"
    )
    render json: @txns
  end
end
